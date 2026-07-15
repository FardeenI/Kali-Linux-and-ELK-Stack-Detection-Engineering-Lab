variable "aws_region" {
	type    = string
	default = "us-east-1"
}

variable "kali_ami" {
	type        = string
	description = "AMI ID for the Kali Linux attacker instance (region-specific; requires AWS Marketplace subscription)"
}

variable "windows_ami" {
	type        = string
	description = "AMI ID for the Windows target instance (region-specific)"
}

variable "ubuntu_ami" {
	type        = string
	description = "AMI ID for the Ubuntu SIEM instance (region-specific)"
}

variable "key_name" {
	type        = string
	description = "Name of an existing EC2 key pair in your AWS account used for SSH/RDP access"
}

variable "operator_ip_1" {
	type        = string
	description = "An operator public IP in CIDR notation (e.g. 1.2.3.4/32) allowed to access the lab instances"
}

variable "operator_ip_2" {
	type        = string
	description = "An operator public IP in CIDR notation (e.g. 1.2.3.4/32) allowed to access the lab instances"
}

variable "operator_ip_3" {
	type        = string
	description = "An operator public IP in CIDR notation (e.g. 1.2.3.4/32) allowed to access the lab instances"
}

# --- GitHub Actions automation (optional) ---
# Leave github_token blank (the default) to skip this entirely and set up
# repo secrets / the self-hosted runner manually, as described in the
# detections-as-code section of README.md.

variable "github_token" {
	type        = string
	description = "Fine-grained GitHub PAT scoped to your fork, with Secrets: read/write (creates the ELASTIC_URL/ELASTIC_PASSWORD secrets) and Administration: read/write (registers the self-hosted runner). Leave blank to skip automated secret/runner setup."
	default     = ""
	sensitive   = true
}

variable "github_owner" {
	type        = string
	description = "GitHub username or org that owns your fork of this repo (required if github_token is set)"
	default     = ""
}

variable "github_repo" {
	type        = string
	description = "Name of your forked repo, without the owner (required if github_token is set)"
	default     = ""
}

variable "github_runner_version" {
	type        = string
	description = "actions/runner release version to install on the Ubuntu SIEM instance (check https://github.com/actions/runner/releases for the latest)"
	default     = "2.321.0"
}
