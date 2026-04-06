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
