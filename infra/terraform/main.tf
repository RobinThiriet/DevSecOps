terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-3"
}

variable "vpc_id" {
  type        = string
  description = "VPC dans lequel déployer VulnShop"
}

variable "admin_cidr" {
  type        = string
  description = "Plage IP autorisée pour l'administration (VPN d'entreprise)"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Sous-réseaux privés pour la base de données"
}

resource "aws_kms_key" "main" {
  description         = "Chiffrement des données VulnShop"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RootAccount"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

data "aws_caller_identity" "current" {}

# --- S3 : privé, chiffré KMS, versionné, journalisé --------------------------
resource "aws_s3_bucket" "uploads" {
  #checkov:skip=CKV_AWS_144:Réplication inter-région non requise pour ce lab
  #checkov:skip=CKV2_AWS_62:Notifications d'événements non requises
  #checkov:skip=CKV2_AWS_61:Cycle de vie géré par un autre module
  bucket = "vulnshop-uploads"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_logging" "uploads" {
  bucket        = aws_s3_bucket.uploads.id
  target_bucket = "vulnshop-access-logs"
  target_prefix = "uploads/"
}

# --- Réseau : SSH réservé au VPN, base de données non exposée ----------------
resource "aws_security_group" "web" {
  name        = "vulnshop-web"
  description = "Trafic entrant de VulnShop"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH depuis le VPN uniquement"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "HTTPS sortant"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "db" {
  name       = "vulnshop-db"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "db" {
  name   = "vulnshop-postgres"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "all"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1"
  }
}

# --- Base de données : privée, chiffrée, mot de passe géré par AWS -----------
resource "aws_db_instance" "db" {
  identifier                          = "vulnshop-db"
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "vulnshop"
  manage_master_user_password         = true
  db_subnet_group_name                = aws_db_subnet_group.db.name
  parameter_group_name                = aws_db_parameter_group.db.name
  vpc_security_group_ids              = [aws_security_group.web.id]
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.main.arn
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  multi_az                            = true
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  backup_retention_period             = 7
  monitoring_interval                 = 60
  monitoring_role_arn                 = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/rds-monitoring"
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.main.arn
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
}

# --- IAM : moindre privilège --------------------------------------------------
resource "aws_iam_policy" "app" {
  name = "vulnshop-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })
}

resource "aws_iam_role" "web" {
  name = "vulnshop-web"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "web" {
  role       = aws_iam_role.web.name
  policy_arn = aws_iam_policy.app.arn
}

resource "aws_iam_instance_profile" "web" {
  name = "vulnshop-web"
  role = aws_iam_role.web.name
}

# --- EC2 : IMDSv2 obligatoire, disque chiffré, monitoring ---------------------
resource "aws_instance" "web" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted = true
  }
}
