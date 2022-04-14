# AWS required providers
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }

  required_version = ">= 0.14.9"
}

provider "aws" {
  profile = "default"
  region  = "ap-south-1"
}


#Creating a security group for our private server
resource "aws_security_group" "SGmain" {
  name        = "SGmain"
  description = "security group for main server"
  vpc_id      = "vpc-08ec6bc523e3e3a20"


  ingress {
    description      = "SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "SGmain"
  }
}


# creating a private EC2 instance names mainServer
resource "aws_instance" "main_server" {
  ami           = "ami-0851b76e8b1bce90b"
  instance_type = "t2.micro"
  key_name = "terraformkey"
  vpc_security_group_ids = [ aws_security_group.SGmain.id ]

  provisioner "remote-exec" {
	inline = [
		"sudo apt --yes install nginx",
		"sudo ufw allow 'Nginx HTTP'",
    "sudo unlink /etc/nginx/sites-enabled/default",
    "sudo git clone https://github.com/cloudacademy/static-website-example.git /var/www/static-website-example",
    "sudo git clone https://github.com/Vishnu3125/nginx-config.git /etc/nginx/sites-available/nginx-config",
    "sudo ln -s /etc/nginx/sites-available/nginx-config/nginx-server.conf /etc/nginx/sites-enabled/nginx-server.conf",
    "sudo systemctl restart nginx"
	]
	
	connection {
		type = "ssh"
		user = "ubuntu"
		private_key = file("./terraformkey.pem")
		host = self.public_ip
	}
  }

  tags = {
    Name = "mainServer"
  }
}


#Creating a security group for our proxy server
resource "aws_security_group" "SGproxy" {
  name        = "SGproxy"
  description = "security group for proxy server"
  vpc_id      = "vpc-08ec6bc523e3e3a20"


  ingress {
    description      = "SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "HTTP"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "SGproxy"
  }
}


# creating a public EC2 instance named proxyServer
resource "aws_instance" "proxy_server" {
  ami           = "ami-0851b76e8b1bce90b"
  instance_type = "t2.micro"
  key_name = "terraformkey"
  vpc_security_group_ids = [ aws_security_group.SGproxy.id ]

  provisioner "remote-exec" {
	inline = [
		"sudo apt --yes install nginx",
		"sudo ufw allow 'Nginx HTTP'",
    "sudo unlink /etc/nginx/sites-enabled/default",
    "sudo git clone https://github.com/Vishnu3125/nginx-config.git /etc/nginx/sites-available/nginx-config",
    "sudo ln -s /etc/nginx/sites-available/nginx-config/nginx-proxy.conf /etc/nginx/sites-enabled/nginx-proxy.conf",
		"sudo sed -i 's/serveripaddress/${aws_instance.main_server.private_ip}/g' /etc/nginx/sites-available/nginx-config/nginx-proxy.conf ",
    "sudo systemctl restart nginx",
	]
	
	connection {
		type = "ssh"
		user = "ubuntu"
		private_key = file("./terraformkey.pem")
		host = self.public_ip
	}
  }

  tags = {
    Name = "proxyServer"
  }
}


#configuring inbound rules of mainServer to allow proxyServer SG
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  # cidr_blocks       = ["${aws_instance.proxy_server.private_ip}/32"]
  # cidr_blocks       = ["${aws_security_group.SGproxy.id}"]
  source_security_group_id = aws_security_group.SGproxy.id
  security_group_id = aws_security_group.SGmain.id
}