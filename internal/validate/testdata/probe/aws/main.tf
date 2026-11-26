terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
    }
  }
}

provider "aws" {
  region                      = "eu-west-3"
  access_key                  = "FAKE-OFFLINE-PLAN"
  secret_key                  = "FAKE-OFFLINE-PLAN"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

resource "aws_vpc" "v" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_subnet" "a" {
  vpc_id            = aws_vpc.v.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-west-3a"
}

resource "aws_subnet" "b" {
  vpc_id            = aws_vpc.v.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-west-3b"
}

resource "aws_security_group" "sg" {
  name   = "probe"
  vpc_id = aws_vpc.v.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_kms_key" "k" {
  enable_key_rotation = true
}

resource "aws_iam_role" "eks" {
  name = "probe-eks"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "eks.amazonaws.com" } }]
  })
}

resource "aws_eks_cluster" "c" {
  name     = "probe"
  role_arn = aws_iam_role.eks.arn
  vpc_config {
    subnet_ids              = [aws_subnet.a.id, aws_subnet.b.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.k.arn
    }
  }
}

resource "aws_iam_user" "injected" {
  name = "probe-injected"
}
