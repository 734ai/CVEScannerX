"""Configuration and cache utilities for CVEScannerX."""

import os
import json
import time
import pickle
from typing import Any, Dict, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class ConfigLoader:
    """Configuration loader and validator."""
    
    @staticmethod
    def load_config(config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise

class Cache:
    """Cache implementation for API responses and scan results."""
    
    def __init__(self, config: Dict):
        """Initialize cache with configuration."""
        self.config = config['cache']
        self.cache_dir = self.config['settings']['directory']
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, key: str, cache_type: str) -> str:
        """Get the file path for a cache entry."""
        return os.path.join(self.cache_dir, f"{cache_type}_{key}.cache")

    def _is_valid(self, timestamp: float, ttl: int) -> bool:
        """Check if a cache entry is still valid."""
        return (time.time() - timestamp) < ttl

    def get(self, key: str, cache_type: str = 'api_responses') -> Optional[Any]:
        """Retrieve an item from cache if it exists and is valid."""
        if not self.config['enabled'] or not self.config['types'][cache_type]['enabled']:
            return None
            
        cache_path = self._get_cache_path(key, cache_type)
        if not os.path.exists(cache_path):
            return None
            
        try:
            with open(cache_path, 'rb') as f:
                data = pickle.load(f)
                
            if self._is_valid(data['timestamp'], self.config['types'][cache_type]['ttl']):
                return data['value']
            else:
                os.remove(cache_path)
                return None
        except Exception as e:
            logger.error(f"Error reading from cache: {e}")
            return None

    def set(self, key: str, value: Any, cache_type: str = 'api_responses') -> None:
        """Store an item in cache."""
        if not self.config['enabled'] or not self.config['types'][cache_type]['enabled']:
            return
            
        cache_path = self._get_cache_path(key, cache_type)
        try:
            with open(cache_path, 'wb') as f:
                pickle.dump({
                    'timestamp': time.time(),
                    'value': value
                }, f)
        except Exception as e:
            logger.error(f"Error writing to cache: {e}")

    def clear(self, cache_type: Optional[str] = None) -> None:
        """Clear cache entries."""
        try:
            if cache_type:
                pattern = f"{cache_type}_*.cache"
            else:
                pattern = "*.cache"
                
            for cache_file in os.listdir(self.cache_dir):
                if cache_file.endswith('.cache') and (not cache_type or cache_file.startswith(f"{cache_type}_")):
                    os.remove(os.path.join(self.cache_dir, cache_file))
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            raise
