terraform {
	required_providers {
		aws = {
			source = "hashicorp/aws"
			version = "~> 5.0"
		}
	}
}

provider "aws" {
	region = var.aws_region
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

  {
    echo "network.host: 0.0.0.0"
    echo "discovery.type: single-node"
    echo "xpack.security.enabled: false"
  } > /etc/elasticsearch/elasticsearch.yml

  # Elasticsearch 8.x package install populates the keystore with SSL passwords
  # that conflict with xpack.security.enabled: false - wipe and recreate it empty
  # This change disables the SSL configuration, so log traffic communicated 
  # between the Windows host and Elasticsearch does not travel through a secure channel.
  # This risk of MITM attack imposed by this configuration change is mitigated by the lab environment's private nature,
  # in that instances are deployed to a private AWS VPC, and is acceptable for 
  # the learning goals of the lab.
  rm -f /etc/elasticsearch/elasticsearch.keystore
  /usr/share/elasticsearch/bin/elasticsearch-keystore create

  echo 'server.host: "0.0.0.0"' >> /etc/kibana/kibana.yml

  # Restore ownership after root-run install steps altered it
  chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/

  systemctl enable elasticsearch kibana
  systemctl start elasticsearch kibana
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

  # Configure Winlogbeat - point at Elasticsearch and Kibana, enable dashboard setup
  (Get-Content "$wlbPath\winlogbeat.yml") `
    -replace 'localhost:9200', '${aws_instance.ubuntu_vm.private_ip}:9200' `
    -replace '#setup\.dashboards\.enabled: false', 'setup.dashboards.enabled: true' `
    -replace '#host: "localhost:5601"', 'host: "${aws_instance.ubuntu_vm.private_ip}:5601"' |
    Set-Content "$wlbPath\winlogbeat.yml"

  # Install and start Winlogbeat service
  powershell -ExecutionPolicy Bypass -File "$wlbPath\install-service-winlogbeat.ps1"
  Start-Service winlogbeat

  # Load Kibana index template and pre-built dashboards
  & "$wlbPath\winlogbeat.exe" setup --dashboards -c "$wlbPath\winlogbeat.yml"
  </powershell>
  EOF
}
