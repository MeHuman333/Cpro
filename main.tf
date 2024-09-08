terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}

# Create a key pair
resource "aws_key_pair" "example" {
  key_name   = "Sai"
  public_key = file("~/.ssh/id_ed25519.pub")
}

# Create a security group to allow SSH
resource "aws_security_group" "allow_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = aws_vpc.main.id  # Assuming you have a VPC created already

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["<your_IP>/32"]  # Replace with your actual IP address
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_ssh"
  }
}

# EC2 instance with security group attached
resource "aws_instance" "server" {
  ami           = "ami-0522ab6e1ddcc7055"
  instance_type = var.instance_type
  key_name      = "Sai"
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]  # Attach the security group

  tags = {
    Name = "${terraform.workspace}_server"
  }

  provisioner "remote-exec" {
    inline = [
      "cat /etc/os-release",
      "mkdir -p /home/ubuntu/.ssh",
      "echo '${var.ssh_public_key}' >> /home/ubuntu/.ssh/authorized_keys",
      "chmod 600 /home/ubuntu/.ssh/authorized_keys",
      "chown -R ubuntu:ubuntu /home/ubuntu/.ssh"
    ]
  }

  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ubuntu"
    private_key = file(var.ssh_private_key)
  }

  provisioner "local-exec" {
    command = "echo '${self.public_ip} ansible_user=ubuntu ansible_private_key_file=~/.ssh/id_ed25519' > inventory.ini"
  }

  provisioner "local-exec" {
    command = "ansible-playbook -u ubuntu -i inventory.ini -e 'ansible_python_interpreter=/usr/bin/python3' ansible-playbook.yml"
  }
}
