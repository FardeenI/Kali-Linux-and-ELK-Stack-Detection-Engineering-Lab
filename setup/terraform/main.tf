terraform {
	required_providers {
		aws = {
			source = "hashicorp/aws"
			version = "~> 5.0"
		}
		random = {
			source  = "hashicorp/random"
			version = "~> 3.0"
		}
		github = {
			source  = "integrations/github"
			version = "~> 6.0"
		}
	}
}

provider "aws" {
	region = var.aws_region
}

# Only used if var.github_token is set - see the "GitHub Actions automation
# (optional)" section of README.md. A blank token is a valid provider
# configuration; it just means the github_actions_secret resources below
# are never created (count = 0), so no API calls are made against it.
provider "github" {
	token = var.github_token
	owner = var.github_owner
}

# Elasticsearch/Kibana must have xpack.security enabled for the Detection
# Engine (rules, alerts, Get Started page) to work - Kibana's RBAC and
# encrypted-saved-objects features depend on ES security APIs even when TLS
# stays disabled. Credentials are provisioned via the ES file realm
# (elasticsearch-users), which writes users directly to disk at boot instead
# of requiring a running cluster or CLI output parsing.
resource "random_password" "admin_password" {
	length  = 20
	special = false
}

resource "random_password" "kibana_service_password" {
	length  = 20
	special = false
}

resource "random_password" "winlogbeat_password" {
	length  = 20
	special = false
}

# GitHub Actions automation (optional) - wires the ELASTIC_URL/ELASTIC_PASSWORD
# secrets that development/upload_to_elastic.py needs, replacing the manual
# "add repo secrets" step. count = 0 (skipped entirely) when var.github_token
# is blank, so this is opt-in and doesn't force every learner to have a PAT.
resource "github_actions_secret" "elastic_url" {
	count           = var.github_token != "" ? 1 : 0
	repository      = var.github_repo
	secret_name     = "ELASTIC_URL"
	# The self-hosted runner always lives on this same Ubuntu instance as
	# Kibana (see deploy.yml), so localhost avoids the AWS IGW hairpin
	# limitation that breaks a box from reaching its own public IP.
	value ="http://localhost:5601"
}

resource "github_actions_secret" "elastic_password" {
	count           = var.github_token != "" ? 1 : 0
	repository      = var.github_repo
	secret_name     = "ELASTIC_PASSWORD"
	value =random_password.admin_password.result
}

resource "aws_servicecatalogappregistry_application" "lab" {
	name        = "DetectionEngineeringLab"
	description = "Kali attacker, Windows target, and Ubuntu SIEM for detection engineering"
}

resource "aws_security_group" "kali_sg" {
        name        = "DetectionEngineeringLab-Kali"
        description = "Applied to Kali attacker instance to accept inbound SSH and send outbound traffic"
        tags = {
                Name           = "Detection Engineering Lab NACL - Kali Attacker"
                Project        = "Kali and ELK Stack Detection Engineering Lab"
                awsApplication = aws_servicecatalogappregistry_application.lab.arn
        }

        ingress {
                description = "SSH access restricted to operator IP"
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = [var.operator_ip_1, var.operator_ip_2, var.operator_ip_3]
        }

        egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
        }
}

resource "aws_security_group" "windows_sg" {
        name        = "DetectionEngineeringLab-Windows"
        description = "Applied to Windows target to accept inbound traffic from Kali, inbound RDP, and send outbound traffic"
        tags = {
                Name           = "Detection Engineering Lab NACL - Windows Target"
                Project        = "Kali and ELK Stack Detection Engineering Lab"
                awsApplication = aws_servicecatalogappregistry_application.lab.arn
        }

        ingress {
                description = "RDP access restricted to operator IP"
                from_port   = 3389
                to_port     = 3389
                protocol    = "tcp"
                cidr_blocks = [var.operator_ip_1, var.operator_ip_2, var.operator_ip_3]
        }

        ingress {
                description     = "All traffic from Kali attacker"
                from_port       = 0
                to_port         = 0
                protocol        = "-1"
                security_groups = [aws_security_group.kali_sg.id]
        }

        egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
        }
}

resource "aws_security_group" "ubuntu_sg" {
        name        = "DetectionEngineeringLab-Ubuntu"
        description = "Applied to Ubuntu SIEM to accept inbound logs and dashboards from Windows, inbound SSH, and send outbound traffic"
        tags = {
                Name           = "Detection Engineering Lab NACL - Ubuntu SIEM"
                Project        = "Kali and ELK Stack Detection Engineering Lab"
                awsApplication = aws_servicecatalogappregistry_application.lab.arn
        }

        ingress {
                description = "SSH access restricted to operator IP"
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = [var.operator_ip_1, var.operator_ip_2, var.operator_ip_3]
        }

        ingress {
                description     = "Elasticsearch accessible only from Windows instance SG"
                from_port       = 9200
                to_port         = 9200
                protocol        = "tcp"
                security_groups = [aws_security_group.windows_sg.id]
        }

        ingress {
                description     = "Kibana dashboard setup traffic from Windows Winlogbeat"
                from_port       = 5601
                to_port         = 5601
                protocol        = "tcp"
                security_groups = [aws_security_group.windows_sg.id]
        }

        ingress {
                description = "Kibana interface access restricted to operator IP"
                from_port   = 5601
                to_port     = 5601
                protocol    = "tcp"
                cidr_blocks = [var.operator_ip_1, var.operator_ip_2, var.operator_ip_3]
        }

        egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
        }
}

resource "aws_instance" "kali_linux" {
	ami = var.kali_ami
	instance_type = "t2.medium"
	vpc_security_group_ids = [aws_security_group.kali_sg.id]
	key_name = var.key_name

	tags = {
		Name           = "Kali Linux"
		Project        = "Kali and ELK Stack Detection Engineering Lab"
		awsApplication = aws_servicecatalogappregistry_application.lab.arn
	}

	user_data = <<-EOF
  #!/bin/bash
  set -e

  apt-get update
  apt-get full-upgrade -y

  # Pre-seed debconf answers to prevent interactive prompts
  echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
  echo "kismet-capture-common kismet-capture-common/install-users string kali" | debconf-set-selections

  DEBIAN_FRONTEND=noninteractive apt-get install -y kali-linux-default
  EOF
}

resource "aws_instance" "ubuntu_vm" {
	ami = var.ubuntu_ami
	instance_type = "t2.large"
	vpc_security_group_ids = [aws_security_group.ubuntu_sg.id]
	key_name = var.key_name

	root_block_device {
		volume_size = 50
		volume_type = "gp3"
	}

	tags = {
		Name           = "SIEM (Elasticsearch, Kibana) - Ubuntu"
		Project        = "Kali and ELK Stack Detection Engineering Lab"
		awsApplication = aws_servicecatalogappregistry_application.lab.arn
	}

	user_data = <<-EOF
  #!/bin/bash
  set -e
  sleep 30

  apt-get update
  apt-get install -y curl apt-transport-https

  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
    gpg --dearmor -o /usr/share/keyrings/elastic.gpg

  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic.list

  apt-get update
  apt-get install -y elasticsearch kibana

  # xpack.security must stay enabled - the Detection Engine (rules, alerts,
  # Get Started page) depends on ES's security/RBAC APIs to determine
  # privileges, even though TLS stays disabled (private VPC, out of scope
  # for this lab - same trade-off as before).
  {
    echo "network.host: 0.0.0.0"
    echo "discovery.type: single-node"
    echo "xpack.security.enabled: true"
    echo "xpack.security.http.ssl.enabled: false"
    echo "xpack.security.transport.ssl.enabled: false"
  } > /etc/elasticsearch/elasticsearch.yml

  # Provision users via the file realm - writes directly to disk, no need to
  # query a running cluster or parse elasticsearch-reset-password output.
  # labadmin: superuser for you to log into the Kibana UI (get the generated
  #   password with `terraform output -raw kibana_admin_password`).
  # kibana_service: kibana_system role, used by Kibana itself.
  # winlogbeat_writer: superuser, used by Winlogbeat for ingest + dashboard
  #   setup (scoped-down roles are a good follow-up, not required for the lab).
  /usr/share/elasticsearch/bin/elasticsearch-users useradd labadmin -p '${random_password.admin_password.result}' -r superuser
  /usr/share/elasticsearch/bin/elasticsearch-users useradd kibana_service -p '${random_password.kibana_service_password.result}' -r kibana_system
  /usr/share/elasticsearch/bin/elasticsearch-users useradd winlogbeat_writer -p '${random_password.winlogbeat_password.result}' -r superuser

  {
    echo 'server.host: "0.0.0.0"'
    echo 'elasticsearch.username: "kibana_service"'
    echo 'elasticsearch.password: "${random_password.kibana_service_password.result}"'
  } >> /etc/kibana/kibana.yml

  # Kibana needs its own encryption key for encrypted saved objects (rule
  # actions/connectors) regardless of ES security state.
  /usr/share/kibana/bin/kibana-encryption-keys generate -q --force >> /etc/kibana/kibana.yml

  # Restore ownership after root-run install steps altered it
  chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/ /etc/elasticsearch/

  systemctl enable elasticsearch kibana
  systemctl start elasticsearch kibana

  # Self-hosted GitHub Actions runner (optional) - registers this box as the
  # runner deploy.yml's "deploy" job targets, replacing the manual config.sh
  # steps in the README. Skipped entirely when github_token is blank, so this
  # is opt-in and doesn't force a PAT on learners who don't want CI/CD wired
  # up yet.
  GITHUB_TOKEN="${var.github_token}"
  if [ -n "$GITHUB_TOKEN" ]; then
    GITHUB_OWNER="${var.github_owner}"
    GITHUB_REPO="${var.github_repo}"
    RUNNER_VERSION="${var.github_runner_version}"

    apt-get install -y jq

    REG_TOKEN=$(curl -s -X POST \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com/repos/$GITHUB_OWNER/$GITHUB_REPO/actions/runners/registration-token" \
      | jq -r .token)

    mkdir -p /home/ubuntu/actions-runner
    cd /home/ubuntu/actions-runner
    curl -o actions-runner-linux-x64.tar.gz -L \
      "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-x64-$RUNNER_VERSION.tar.gz"
    tar xzf actions-runner-linux-x64.tar.gz
    chown -R ubuntu:ubuntu /home/ubuntu/actions-runner

    runuser -l ubuntu -c "cd /home/ubuntu/actions-runner && ./config.sh --url https://github.com/$GITHUB_OWNER/$GITHUB_REPO --token $REG_TOKEN --unattended --labels self-hosted --name siem-runner"

    ./svc.sh install ubuntu
    ./svc.sh start
  fi
  EOF
}

resource "aws_instance" "windows_server" {
	ami = var.windows_ami
	instance_type = "t3.medium"
	depends_on = [aws_instance.ubuntu_vm]
	vpc_security_group_ids = [aws_security_group.windows_sg.id]
	key_name = var.key_name

	tags = {
		Name           = "Target (Sysmon, Winlogbeat) - Windows"
		Project        = "Kali and ELK Stack Detection Engineering Lab"
		awsApplication = aws_servicecatalogappregistry_application.lab.arn
	}
	user_data = <<-EOF
  <powershell>
  # Install Sysmon
  Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Sysmon.zip
  Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon
  Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\sysmon.xml
  C:\Sysmon\Sysmon64.exe -accepteula -i C:\sysmon.xml

  # Install Winlogbeat
  Invoke-WebRequest https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.17.0-windows-x86_64.zip -OutFile C:\winlogbeat.zip
  Expand-Archive C:\winlogbeat.zip -DestinationPath "C:\Program Files\Winlogbeat"
  $wlbPath = "C:\Program Files\Winlogbeat\winlogbeat-8.17.0-windows-x86_64"

  # Configure Winlogbeat - point at Elasticsearch and Kibana, enable dashboard
  # setup, and authenticate as winlogbeat_writer (ES security is enabled, so
  # unauthenticated ingest/dashboard-setup calls are rejected)
  (Get-Content "$wlbPath\winlogbeat.yml") `
    -replace 'localhost:9200', '${aws_instance.ubuntu_vm.private_ip}:9200' `
    -replace '#username: "elastic"', 'username: "winlogbeat_writer"' `
    -replace '#password: "changeme"', 'password: "${random_password.winlogbeat_password.result}"' `
    -replace '#setup\.dashboards\.enabled: false', 'setup.dashboards.enabled: true' `
    -replace '#host: "localhost:5601"', 'host: "${aws_instance.ubuntu_vm.private_ip}:5601"' |
    Set-Content "$wlbPath\winlogbeat.yml"

  # Allow ICMP echo requests (ping) through Windows Firewall
  netsh advfirewall firewall add rule name="Allow ICMPv4" protocol="icmpv4:8,any" dir=in action=allow

  # Allow SMB inbound — blocked by default on the Public network profile AWS instances land on
  netsh advfirewall firewall add rule name="Allow SMB" protocol=TCP dir=in localport=445 action=allow

  # Enable logon failure auditing — required to generate Event ID 4625 in the Security log
  auditpol /set /subcategory:"Logon" /failure:enable

  # Enable account lockout auditing — required to generate Event ID 4740
  auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

  # Enable NTLM credential validation auditing — required to generate Event ID 4776
  auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

  # Enable object access auditing — required to generate Event ID 4698 (scheduled task created)
  auditpol /set /subcategory:"Other Object Access Events" /success:enable

  # Enable Filtering Platform connection auditing — required to generate Event IDs 5156/5157
  # (permitted/blocked connections) for every inbound SYN, regardless of whether a listener
  # exists on the port. Sysmon Event ID 3 only logs connections to ports with an actual
  # listener, so it can't see attempts against closed ports during a port scan.
  auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

  # Set low lockout policy and create throwaway victim account for brute force / spray simulation
  # Targets labvictim instead of Administrator to avoid locking out the access account
  net accounts /lockoutthreshold:5 /lockoutwindow:5 /lockoutduration:5
  net user labvictim 'P@ssw0rd-Real-2026!' /add
  net localgroup "Remote Desktop Users" labvictim /add

  # Install and start Winlogbeat service
  powershell -ExecutionPolicy Bypass -File "$wlbPath\install-service-winlogbeat.ps1"
  Start-Service winlogbeat

  # Load Kibana index template and pre-built dashboards
  & "$wlbPath\winlogbeat.exe" setup --dashboards -c "$wlbPath\winlogbeat.yml"
  </powershell>
  EOF
}

output "kibana_admin_password" {
	description = "Password for the 'labadmin' superuser - log into Kibana at http://<ubuntu-public-ip>:5601 with labadmin / this password. Retrieve with: terraform output -raw kibana_admin_password"
	value       = random_password.admin_password.result
	sensitive   = true
}
