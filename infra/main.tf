# =============================================================================
# infra/main.tf - Infraestrutura da TaskFlow (Modulo 5 - IaC)
#
# Corrigido a partir do main.insecure.tf da Aula 6 (Encontro 12).
# Uso DIDATICO: validado com "terraform validate", Checkov e Trivy config.
# NAO executar "terraform apply" em conta AWS real sem orientacao do professor.
#
# Correcoes em relacao ao main.insecure.tf:
#   FALHA 1 -> tags de governanca (default_tags no provider)
#   FALHA 2 -> bloqueio de acesso publico ativado nos 4 campos
#   FALHA 3 -> ACLs desativadas (BucketOwnerEnforced) em vez de "public-read"
#   FALHA 4 -> criptografia em repouso com chave KMS gerenciada pelo cliente
#   FALHA 5 -> versionamento habilitado
#   FALHA 6 -> ingresso restrito a uma variavel de IP (nunca 0.0.0.0/0)
#   FALHA 7 -> egresso restrito a HTTPS para uma faixa interna (variavel)
#   EXTRA   -> access logging do bucket em um bucket de logs dedicado
#   EXTRA   -> ciclo de vida (versoes antigas e uploads incompletos)
#
# Toda supressao (checkov:skip / trivy:ignore) tem justificativa na propria
# linha, conforme as Rubricas Gerais (secao 2.d).
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Em producao o state ficaria em backend remoto criptografado (ex.: S3 +
  # DynamoDB para lock), porque o state pode conter valores sensiveis.
  # Backend local e aceitavel apenas neste contexto didatico.
}

provider "aws" {
  region = var.aws_region

  # FALHA 1 corrigida: toda a infraestrutura recebe tags de governanca.
  default_tags {
    tags = {
      Projeto  = "taskflow-devsecops"
      Ambiente = "estudo"
      Owner    = "grupo-taskflow"
    }
  }
}

# -----------------------------------------------------------------------------
# Variaveis
# -----------------------------------------------------------------------------
variable "aws_region" {
  description = "Regiao AWS dos recursos."
  type        = string
  default     = "us-east-1"
}

variable "allowed_cidr" {
  description = "Faixa (CIDR) autorizada a acessar a aplicacao via HTTPS. Nunca 0.0.0.0/0."
  type        = string
  default     = "192.168.15.0/24"

  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr deve ser um CIDR valido e diferente de 0.0.0.0/0."
  }
}

variable "egress_cidr" {
  description = "Faixa interna para onde a aplicacao pode sair via HTTPS (proxy/VPC endpoints)."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.egress_cidr, 0)) && var.egress_cidr != "0.0.0.0/0"
    error_message = "egress_cidr deve ser um CIDR valido e diferente de 0.0.0.0/0."
  }
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Chave KMS (FALHA 4): criptografia com chave gerenciada pelo cliente
# -----------------------------------------------------------------------------
resource "aws_kms_key" "taskflow" {
  description             = "Chave KMS do bucket de dados da TaskFlow"
  enable_key_rotation     = true # rotacao anual automatica
  deletion_window_in_days = 30

  # Politica explicita: so a propria conta administra a chave.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdministracaoPelaPropriaConta"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "taskflow" {
  name          = "alias/taskflow-dados"
  target_key_id = aws_kms_key.taskflow.key_id
}

# -----------------------------------------------------------------------------
# Bucket de LOGS (destino do access logging do bucket de dados)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "taskflow_logs" {
  # checkov:skip=CKV_AWS_18:Este e o proprio bucket de destino dos logs; logar o bucket de logs criaria recursao.
  # checkov:skip=CKV_AWS_145:O destino de server access logging do S3 so aceita SSE-S3 (AES256), nao SSE-KMS.
  # checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo/custo do laboratorio; versionamento cobre recuperacao.
  # checkov:skip=CKV2_AWS_62:Nenhum consumidor de eventos para logs de acesso; notificacoes nao agregam controle aqui.
  bucket = "taskflow-logs-devsecops-2026"
}

resource "aws_s3_bucket_ownership_controls" "taskflow_logs" {
  bucket = aws_s3_bucket.taskflow_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced" # ACLs desativadas
  }
}

resource "aws_s3_bucket_public_access_block" "taskflow_logs" {
  bucket                  = aws_s3_bucket.taskflow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Justificativa do ignore abaixo: o destino de server access logging do S3 so
# aceita SSE-S3 (AES256); SSE-KMS nao e suportado pela AWS para este uso
# (a propria descricao da regra AWS-0132 do Trivy reconhece essa excecao).
#trivy:ignore:AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "taskflow_logs" {
  bucket = aws_s3_bucket.taskflow_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "taskflow_logs" {
  bucket = aws_s3_bucket.taskflow_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "taskflow_logs" {
  bucket = aws_s3_bucket.taskflow_logs.id

  rule {
    id     = "retencao-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Permite que SOMENTE o servico de logging do S3, e apenas para o bucket de
# dados desta conta, grave no bucket de logs.
resource "aws_s3_bucket_policy" "taskflow_logs" {
  bucket = aws_s3_bucket.taskflow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogsPolicy"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.taskflow_logs.arn}/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.taskflow_dados.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.taskflow_logs]
}

# -----------------------------------------------------------------------------
# Bucket de DADOS da TaskFlow
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "taskflow_dados" {
  # checkov:skip=CKV_AWS_144:Replicacao entre regioes fora do escopo/custo do laboratorio; versionamento cobre recuperacao.
  # checkov:skip=CKV2_AWS_62:A aplicacao nao consome eventos do bucket; notificacoes sem consumidor nao agregam controle.
  bucket = "taskflow-dados-devsecops-2026"
}

# FALHA 3 corrigida: ACLs desativadas; acesso apenas via IAM.
resource "aws_s3_bucket_ownership_controls" "taskflow_dados" {
  bucket = aws_s3_bucket.taskflow_dados.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# FALHA 2 corrigida: bloqueio de acesso publico nos 4 campos.
resource "aws_s3_bucket_public_access_block" "taskflow_dados" {
  bucket                  = aws_s3_bucket.taskflow_dados.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FALHA 4 corrigida: criptografia em repouso com a chave KMS acima.
resource "aws_s3_bucket_server_side_encryption_configuration" "taskflow_dados" {
  bucket = aws_s3_bucket.taskflow_dados.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.taskflow.arn
    }
    bucket_key_enabled = true
  }
}

# FALHA 5 corrigida: versionamento habilitado.
resource "aws_s3_bucket_versioning" "taskflow_dados" {
  bucket = aws_s3_bucket.taskflow_dados.id
  versioning_configuration {
    status = "Enabled"
  }
}

# EXTRA: access logging do bucket de dados no bucket de logs.
resource "aws_s3_bucket_logging" "taskflow_dados" {
  bucket        = aws_s3_bucket.taskflow_dados.id
  target_bucket = aws_s3_bucket.taskflow_logs.id
  target_prefix = "s3-access/taskflow-dados/"
}

# EXTRA: ciclo de vida - limpa versoes antigas e uploads incompletos.
resource "aws_s3_bucket_lifecycle_configuration" "taskflow_dados" {
  bucket = aws_s3_bucket.taskflow_dados.id

  rule {
    id     = "versoes-antigas-e-uploads-incompletos"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# -----------------------------------------------------------------------------
# Security Group da aplicacao
# -----------------------------------------------------------------------------
resource "aws_security_group" "taskflow_app" {
  # checkov:skip=CKV2_AWS_5:Nao ha EC2/ALB neste modulo; o SG e a definicao de rede que sera anexada quando a aplicacao for implantada.
  name        = "taskflow-app-sg"
  description = "Security group da TaskFlow: HTTPS de entrada restrito e saida restrita"

  # FALHA 6 corrigida: sem SSH aberto; entrada so HTTPS a partir da faixa
  # definida em var.allowed_cidr (validada para nunca ser 0.0.0.0/0).
  ingress {
    description = "HTTPS somente da faixa autorizada"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # FALHA 7 corrigida: saida apenas HTTPS para a faixa interna (proxy /
  # VPC endpoints), em vez de todo o trafego para a internet.
  egress {
    description = "Saida HTTPS somente para a faixa interna"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.egress_cidr]
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
output "bucket_dados" {
  description = "Nome do bucket de dados da TaskFlow"
  value       = aws_s3_bucket.taskflow_dados.bucket
}

output "bucket_logs" {
  description = "Nome do bucket de access logs"
  value       = aws_s3_bucket.taskflow_logs.bucket
}

output "security_group_id" {
  description = "ID do security group da aplicacao"
  value       = aws_security_group.taskflow_app.id
}
