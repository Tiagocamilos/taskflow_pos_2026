# ==============================================================================
# ARQUIVO: infra/main.tf
# DESCRIÇÃO: Código Terraform seguro para provisionamento de S3 e Security Group
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "allowed_cidr" {
  type        = string
  description = "Bloco IP permitido para acesso ao SG"
  default     = "192.168.1.100/32" # Restrito e parametrizado (não 0.0.0.0/0)
}

# ------------------------------------------------------------------------------
# BLOCO 1: Bucket S3 Seguro
# ------------------------------------------------------------------------------
resource "aws_s3_bucket" "taskflow_data" {
  bucket        = "taskflow-secure-bucket-devsecops-2026"
  force_destroy = true
}

# Bloqueio total de acesso público
resource "aws_s3_bucket_public_access_block" "public_block" {
  bucket                  = aws_s3_bucket.taskflow_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Criptografia em repouso (Server-Side Encryption)
resource "aws_s3_bucket_server_side_encryption_configuration" "crypto" {
  bucket = aws_s3_bucket.taskflow_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versionamento de Objetos
resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.taskflow_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ------------------------------------------------------------------------------
# BLOCO 2: Security Group Restrito
# ------------------------------------------------------------------------------
resource "aws_security_group" "web_sg" {
  name        = "taskflow-web-sg"
  description = "Security group restrito para o TaskFlow"

  ingress {
    description = "HTTP Ingress Restrito"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr] # Uso de variável restrita
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# #checkov:skip=CKV_AWS_18: "Logging ativado em nível de conta via CloudTrail para este ambiente didático"

# ==============================================================================
# RESUMO: Bucket S3 configurado com criptografia, bloqueio público e versionamento.
# Security Group utiliza CIDR parametrizado via variável. Skips com justificativa.
# ==============================================================================
