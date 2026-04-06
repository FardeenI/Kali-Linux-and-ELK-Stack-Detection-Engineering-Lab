# Detection Engineering Lab — Kali + ELK on AWS

A Terraform-automated detection engineering lab that deploys a simulated enterprise network to AWS: a Kali Linux attacker, a Windows target instrumented with Sysmon and Winlogbeat, and an Ubuntu SIEM running Elasticsearch and Kibana. Clone the repo, fill in your variables, and have a fully wired lab running in minutes.

---

## Background & Motivation

I try to stay up to date on the latest in tech and cybersecurity through newsletters, blogs, and podcasts. Clint Gibler's [TLDR Sec](https://tldrsec.com/) surfaced a detection engineering lab built by Rafael Martinez that used Terraform to deploy attack/defend infrastructure to AWS — and I wanted to build my own version.

I was deep into computer science coursework at the time, leaning heavily into AI-assisted software development, and it had been a while since I'd done hands-on security engineering. This project was an opportunity to get back to breaking and fixing things, while also learning Infrastructure-as-Code (IaC) with Terraform.

What I found most compelling about this lab's design is its simulation of a small enterprise network hosted on AWS. It removes the memory and storage bottlenecks I typically encounter when running virtual machines on a local hypervisor — and it tears down just as fast as it spins up.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                  AWS Default VPC (us-east-1)                 │
│                                                              │
│   ┌─────────────┐    [all traffic]    ┌──────────────────┐   │
│   │ Kali Linux  │ ──────────────────► │  Windows Server  │   │
│   │  (attacker) │                     │    (target)      │   │
│   │  t2.medium  │                     │   t3.medium      │   │
│   └─────────────┘                     └────────┬─────────┘   │
│                                                │             │
│                                    Winlogbeat (logs → 9200)  │
│                                    Kibana setup  (→ 5601)    │
│                                                │             │
│                                       ┌────────▼─────────┐   │
│                                       │   Ubuntu SIEM    │   │
│                                       │  Elasticsearch   │   │
│                                       │     Kibana       │   │
│                                       │   t2.large       │   │
│                                       └──────────────────┘   │
│                                                              │
│   Operator access: SSH (22) to Kali/Ubuntu                   │
│                    RDP (3389) to Windows                     │
│                    Kibana UI (5601) to Ubuntu                │
└──────────────────────────────────────────────────────────────┘
```

### Components

| Instance | OS | Type | Role |
|---|---|---|---|
| Kali Linux | Kali | t2.medium | Attacker — runs offensive tooling |
| Windows Server | Windows | t3.medium | Target — Sysmon + Winlogbeat |
| Ubuntu SIEM | Ubuntu | t2.large | SIEM — Elasticsearch + Kibana |

**Data flow:** Kali attacks Windows → Sysmon captures detailed Windows events → Winlogbeat ships logs to Elasticsearch → Kibana visualizes them as dashboards.

---

## Prerequisites

Before running `terraform apply`, you need:

1. **AWS account** with an IAM user whose access keys are exported as environment variables:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   ```

2. **EC2 key pair** already created in your AWS account (used for SSH into Kali/Ubuntu and decrypting the Windows RDP password).

3. **Kali Linux AMI subscription** — the Kali AMI is distributed through AWS Marketplace and requires a free subscription before it can be launched. Subscribe before running `terraform apply`.

4. **Terraform** installed ([download](https://developer.hashicorp.com/terraform/install)).

5. **Your public IP(s)** — the security groups restrict SSH, RDP, and Kibana access to operator-specified CIDRs. You'll need to know your public IP(s) in CIDR notation (e.g. `1.2.3.4/32`). Run the following to discover your current public IPv4 address:
   ```bash
   curl -4 ifconfig.me
   ```

6. **SSH client** — for connecting to the Kali and Ubuntu instances. AWS requires key pair files to have strict permissions before use:
   ```bash
   chmod 400 your-key.pem
   ```

7. **RDP client** — for connecting to the Windows instance (e.g. Microsoft Remote Desktop on macOS/Windows, or Remmina on Linux).

8. **Default VPC** — the lab deploys into your AWS account's default VPC. Every new AWS account comes with one per region, but if yours has been deleted you'll need to recreate it via the VPC Console (`Actions → Create default VPC`) before applying. If you'd prefer to deploy into a different VPC, add a `vpc_id` argument to each `aws_security_group` resource in `main.tf` and a `subnet_id` argument to each `aws_instance` resource pointing at a subnet within that VPC.

---

## Quickstart

```bash
# 1. Clone the repo
git clone <repo-url>
cd detection-engineering/setup/terraform

# 2. Create your variables file from the example
cp terraform.tfvars.example terraform.tfvars

# 3. Fill in terraform.tfvars with your values (see file for guidance)
#    - Key pair name
#    - Your public IP(s)
#    - AMI IDs for your region (defaults provided for us-east-1)

# 4. Initialize Terraform (downloads the AWS provider)
terraform init

# 5. Deploy
terraform apply
```

Terraform will output the public IPs of all three instances when the apply completes.

> **Note:** The Windows instance has a `depends_on` the Ubuntu SIEM so that Elasticsearch is running before Winlogbeat tries to connect. Even so, the `user_data` scripts run asynchronously after instance launch — give the lab a few minutes after `apply` completes before expecting logs to appear in Kibana.

---

## Accessing the Lab

| Service | How | Address |
|---|---|---|
| Kali Linux | SSH | `ssh -i your-key.pem kali@<kali-public-ip>` |
| Ubuntu SIEM | SSH | `ssh -i your-key.pem ubuntu@<ubuntu-public-ip>` |
| Kibana | Browser | `http://<ubuntu-public-ip>:5601` |
| Windows | RDP client | `<windows-public-ip>:3389` — decrypt password with your key pair via the AWS Console |

---

## Security Group Design

Three security groups enforce least-privilege access:

- **Kali SG** — inbound SSH from operator IPs only; unrestricted outbound.
- **Windows SG** — inbound RDP from operator IPs; all traffic from the Kali security group (attack traffic). Unrestricted outbound.
- **Ubuntu SG** — inbound SSH from operator IPs; Kibana UI (5601) from operator IPs; Elasticsearch (9200) and Kibana setup traffic (5601) from the Windows security group only.

This means Elasticsearch is never directly reachable from the public internet — only from the Windows instance via its security group membership.

---

## Bootstrap Details

Each instance is bootstrapped via `user_data` on first launch:

**Kali** — runs `apt-get full-upgrade` and installs the `kali-linux-default` metapackage (the standard Kali tool suite). Interactive prompts for Wireshark and Kismet are pre-seeded via `debconf` to prevent the script from hanging.

**Ubuntu (SIEM)** — installs Elasticsearch and Kibana from the official Elastic 8.x APT repository. Elasticsearch is configured as a single-node cluster listening on all interfaces. SSL/TLS (`xpack.security`) is disabled — the Elasticsearch 8.x package pre-populates a keystore with SSL credentials that conflict with disabling security, so the keystore is wiped and recreated empty. This is an intentional trade-off: the MITM risk is acceptable given the lab's private VPC context and that production-grade TLS configuration is out of scope for this lab's learning goals. Kibana is configured to listen on all interfaces so it's reachable via the instance's public IP.

**Windows (Target)** — installs Sysmon using the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) for comprehensive event coverage, then installs Winlogbeat 8.17.0. The Winlogbeat config is patched at boot to point at the Ubuntu instance's private IP for both Elasticsearch (9200) and Kibana (5601), and dashboard setup is enabled so that pre-built Winlogbeat dashboards are automatically loaded into Kibana.

---

## Verifying Deployment

Once instances are running, here's how to confirm everything wired up correctly:

**Kali** — SSH in and spot-check tools are installed:
```bash
which nmap
which msfconsole
which wireshark
```

**Ubuntu** — check service status:
```bash
sudo systemctl status elasticsearch
sudo systemctl status kibana
```

**Windows** — RDP in and open PowerShell to verify Winlogbeat config and service:
```powershell
# Check the config points to the right Elasticsearch/Kibana IPs
Get-Content "C:\Program Files\Winlogbeat\winlogbeat-8.17.0-windows-x86_64\winlogbeat.yml"

# Confirm the service is running
Get-Service winlogbeat
```

Then open `http://<ubuntu-public-ip>:5601` in your browser — navigate to **Dashboards** and you should see the pre-built Winlogbeat dashboards populated with Windows event data.

---

## Resource Tracking

All lab resources are tagged and grouped under an **AWS Service Catalog App Registry** application (`DetectionEngineeringLab`). This makes it easy to find and audit every resource the lab created from the AWS Console under **MyApplications**.

---

## Teardown

```bash
terraform destroy
```

This removes all provisioned resources. Because `*.tfstate` is gitignored, your state file is local — don't delete it before running destroy.

---

## Learning Goals

This project was an exercise in several areas:

- **Infrastructure-as-Code with Terraform** — declaring cloud infrastructure as version-controlled code, including EC2 instances, security groups, and dependency ordering between resources.
- **Detection engineering fundamentals** — understanding how attacker activity on a Windows host generates artifacts that flow through Sysmon → Winlogbeat → Elasticsearch → Kibana.
- **Security group design** — modeling a realistic network segmentation policy where the SIEM is only reachable from the Windows target (not the public internet), and the attacker can reach the target but not the SIEM directly.
- **Cloud bootstrapping** — using `user_data` to fully configure instances at launch without manual post-deployment steps, including handling non-interactive package installs and service configuration.
- **Debugging distributed systems** — diagnosing startup ordering issues between Elasticsearch, Kibana, and Winlogbeat; resolving SSL/TLS keystore conflicts; and tracing connectivity problems through security group rules and service logs.

---

## AMI Notes (us-east-1)

The default AMI IDs in `terraform.tfvars.example` target us-east-1. If deploying to another region, look up the equivalent AMIs for your region before applying.

| Instance | Default AMI (us-east-1) |
|---|---|
| Kali Linux | ami-09e99f75cc7592017 |
| Windows Server | ami-06b5375e3af24939c |
| Ubuntu | ami-0ecb62995f68bb549 |
