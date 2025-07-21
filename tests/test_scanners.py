"""Test scanning functionality for CVEScannerX."""

import pytest
from unittest.mock import patch, MagicMock
from src.scanners.local_scanner import LocalScanner
from src.scanners.remote_scanner import RemoteScanner

@pytest.fixture
def sample_config():
    return {
        "features": {
            "scanning": {
                "local": {
                    "enabled": True,
                    "requires_sudo": True,
                    "scan_types": ["packages", "services", "ports"]
                },
                "remote": {
                    "enabled": True,
                    "default_ports": "1-1000",
                    "timeout": 300,
                    "options": {
                        "service_detection": True,
                        "os_detection": True,
                        "script_scan": False
                    }
                }
            }
        }
    }

@pytest.fixture
def local_scanner(sample_config):
    return LocalScanner(sample_config)

@pytest.fixture
def remote_scanner(sample_config):
    return RemoteScanner(sample_config)

def test_local_scanner_packages(local_scanner):
    """Test local package scanning."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout='{"packages": []}',
            stderr='',
            returncode=0
        )
        result = local_scanner.scan_packages()
        assert isinstance(result, dict)
        mock_run.assert_called_once()

def test_local_scanner_services(local_scanner):
    """Test local service scanning."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(
            stdout='{"services": []}',
            stderr='',
            returncode=0
        )
        result = local_scanner.scan_services()
        assert isinstance(result, dict)
        mock_run.assert_called_once()

def test_remote_scanner_args(remote_scanner):
    """Test remote scanner argument building."""
    args = remote_scanner.build_scan_arguments("192.168.1.1")
    assert "-sV" in args  # Service version detection
    assert "-O" in args   # OS detection
    assert "-p" in args   # Port specification
