# VULN-IAC : infrastructure AWS volontairement mal configurée (module 06).
# Ce code n'est JAMAIS appliqué (pas de `terraform apply`) : il sert uniquement
# de cible aux scanners IaC (Checkov, Trivy config).

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "eu-west-3"
}

# IAC-01 : bucket S3 public, sans chiffrement, sans versioning, sans logs
resource "aws_s3_bucket" "uploads" {
  bucket = "vulnshop-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read"
}

# IAC-02 : SSH et base de données ouverts à tout Internet
resource "aws_security_group" "web" {
  name        = "vulnshop-web"
  description = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAC-03 : base de données non chiffrée, publique, mot de passe en clair
resource "aws_db_instance" "db" {
  identifier          = "vulnshop-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "admin123"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# IAC-04 : politique IAM "admin partout"
resource "aws_iam_policy" "app" {
  name = "vulnshop-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# IAC-05 : instance EC2 avec IMDSv1 et disque non chiffré
resource "aws_instance" "web" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]

  root_block_device {
    encrypted = false
  }
}
