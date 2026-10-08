"""Tests for security detectors."""

from src.detectors import (
    detect_ec2_public_ip_with_admin_role,
    detect_hardcoded_secrets,
    detect_overly_permissive_roles,
    detect_public_db_port,
    detect_public_rds,
    detect_public_s3,
    detect_public_ssh,
    detect_unencrypted_rds,
    detect_unencrypted_s3,
    reset_counter,
    run_all_detectors,
)
from src.models import CloudConfig, Severity


def test_detect_public_ssh(sample_config: CloudConfig):
    reset_counter()
    findings = detect_public_ssh(sample_config.resources)
    assert len(findings) >= 1
    assert all(f.severity == Severity.CRITICAL for f in findings)
    assert any("SSH" in f.title for f in findings)


def test_detect_public_db_port(sample_config: CloudConfig):
    reset_counter()
    findings = detect_public_db_port(sample_config.resources)
    assert len(findings) >= 1
    assert any("3306" in f.title for f in findings)


def test_detect_public_s3(sample_config: CloudConfig):
    reset_counter()
    findings = detect_public_s3(sample_config.resources)
    assert len(findings) >= 1
    assert any("logs-public" in f.resource_name for f in findings)


def test_detect_unencrypted_s3(sample_config: CloudConfig):
    reset_counter()
    findings = detect_unencrypted_s3(sample_config.resources)
    assert len(findings) >= 1


def test_detect_public_rds(sample_config: CloudConfig):
    reset_counter()
    findings = detect_public_rds(sample_config.resources)
    assert len(findings) >= 1
    assert any("staging" in f.resource_name for f in findings)


def test_detect_unencrypted_rds(sample_config: CloudConfig):
    reset_counter()
    findings = detect_unencrypted_rds(sample_config.resources)
    assert len(findings) >= 1


def test_detect_overly_permissive_roles(sample_config: CloudConfig):
    reset_counter()
    findings = detect_overly_permissive_roles(sample_config.resources)
    assert len(findings) >= 1
    assert any("admin" in f.title.lower() or "permissive" in f.title.lower() for f in findings)


def test_detect_hardcoded_secrets(sample_config: CloudConfig):
    reset_counter()
    findings = detect_hardcoded_secrets(sample_config.resources)
    assert len(findings) >= 1
    assert any("Lambda" in f.description for f in findings)


def test_detect_ec2_public_ip_with_admin_role(sample_config: CloudConfig):
    reset_counter()
    findings = detect_ec2_public_ip_with_admin_role(sample_config.resources)
    assert len(findings) >= 1
    assert any("jumpbox" in f.resource_name or "admin" in f.description.lower() for f in findings)


def test_run_all_detectors(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    assert len(findings) >= 8  # we expect at least 8 findings from sample
    categories = {f.category for f in findings}
    assert "Network" in categories
    assert "IAM" in categories


def test_no_false_positives_on_clean_config():
    """A config with no misconfigurations should produce zero findings."""
    from src.models import CloudResource

    clean_resources = [
        CloudResource(
            id="sg-clean", type="SecurityGroup", name="clean-sg",
            properties={
                "inbound_rules": [{"protocol": "tcp", "port": 443, "source": "10.0.0.0/8"}],
                "outbound_rules": [],
            },
        ),
        CloudResource(
            id="s3-clean", type="S3Bucket", name="clean-bucket",
            properties={"public_access": False, "encryption": "AES256", "versioning": True},
        ),
    ]
    findings = run_all_detectors(clean_resources)
    assert len(findings) == 0
