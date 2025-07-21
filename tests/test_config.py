"""Test configuration for CVEScannerX."""

import os
import pytest
from src.utils.config import ConfigLoader, Cache

@pytest.fixture
def sample_config():
    return {
        "cache": {
            "enabled": True,
            "settings": {
                "directory": ".cache",
                "max_age": 86400
            },
            "types": {
                "api_responses": {
                    "enabled": True,
                    "ttl": 3600
                },
                "scan_results": {
                    "enabled": True,
                    "ttl": 86400
                }
            }
        }
    }

@pytest.fixture
def cache(sample_config, tmp_path):
    sample_config["cache"]["settings"]["directory"] = str(tmp_path)
    return Cache(sample_config)

def test_cache_set_get(cache):
    """Test basic cache operations."""
    cache.set("test_key", "test_value", "api_responses")
    assert cache.get("test_key", "api_responses") == "test_value"

def test_cache_expiration(cache):
    """Test cache expiration."""
    import time
    cache.config["types"]["api_responses"]["ttl"] = 1  # Set TTL to 1 second
    cache.set("test_key", "test_value", "api_responses")
    time.sleep(2)  # Wait for cache to expire
    assert cache.get("test_key", "api_responses") is None

def test_cache_clear(cache):
    """Test cache clearing."""
    cache.set("test_key1", "test_value1", "api_responses")
    cache.set("test_key2", "test_value2", "scan_results")
    cache.clear("api_responses")
    assert cache.get("test_key1", "api_responses") is None
    assert cache.get("test_key2", "scan_results") == "test_value2"
