"""Tests for Forterra scanner."""

from pathlib import Path
from forterra.scanner import Scanner


def test_scanner_finds_tf_files(tmp_path):
    """Test that the scanner finds .tf files."""
    # Create a test .tf file
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "aws_s3_bucket" "test" { bucket = "my-bucket" }')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    assert len(files) == 1


def test_scanner_detects_public_s3(tmp_path):
    """Test that the scanner catches public S3 buckets."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "public-read"
}
''')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    issues = scanner.scan_files(files)

    assert len(issues) >= 1
    assert any(i["severity"] == "CRITICAL" for i in issues)


def test_scanner_detects_open_security_group(tmp_path):
    """Test that the scanner catches 0.0.0.0/0 in security groups."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    issues = scanner.scan_files(files)

    assert len(issues) >= 1


def test_scanner_detects_public_rds(tmp_path):
    """Test that the scanner catches publicly accessible RDS."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''
resource "aws_db_instance" "main" {
  engine         = "postgres"
  instance_class = "db.t3.micro"
  publicly_accessible = true
}
''')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    issues = scanner.scan_files(files)

    assert any(i["id"] == "FT-RDS-001" for i in issues)


def test_scanner_clean_terraform(tmp_path):
    """Test that secure Terraform passes without issues."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''
resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = false
  storage_encrypted   = true
  backup_retention_period = 7
}
''')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    issues = scanner.scan_files(files)

    # Should not have any RDS-specific critical issues
    rds_critical = [i for i in issues if i["id"].startswith("FT-RDS") and i["severity"] == "CRITICAL"]
    assert len(rds_critical) == 0


def test_scanner_detects_hardcoded_secrets(tmp_path):
    """Test that the scanner catches hardcoded secrets."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('''
resource "aws_db_instance" "main" {
  password = "super_secret_password_123"
}
''')

    scanner = Scanner()
    files = scanner.find_terraform_files(str(tmp_path))
    issues = scanner.scan_files(files)

    assert any(i["id"] == "FT-SEC-001" for i in issues)
