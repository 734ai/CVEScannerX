"""Shodan API client for CVEScannerX."""

import time
import shodan
from typing import Dict, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class ShodanClient:
    """Client for the Shodan API."""
    
    def __init__(self, config: Dict):
        """Initialize Shodan API client."""
        self.config = config['api_config']['shodan']
        self.api = None
        self.last_request_time = 0
        self.min_request_interval = 1.0 / self.config['rate_limit']['requests_per_second']

    def set_api_key(self, api_key: str) -> None:
        """Set up the Shodan API client with an API key."""
        try:
            self.api = shodan.Shodan(api_key)
        except Exception as e:
            logger.error(f"Failed to initialize Shodan API client: {e}")
            raise

    def _rate_limit(self) -> None:
        """Implement rate limiting for API requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def host_lookup(self, ip: str) -> Dict:
        """Look up information about a specific IP address."""
        if not self.api:
            raise RuntimeError("Shodan API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.host(ip)
        except shodan.APIError as e:
            logger.error(f"Shodan API error for IP {ip}: {e}")
            raise

    def search_host(self, 
                   query: str,
                   limit: Optional[int] = 100,
                   offset: Optional[int] = 0) -> Dict:
        """Search for hosts matching the given criteria."""
        if not self.api:
            raise RuntimeError("Shodan API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.search(query, limit=limit, offset=offset)
        except shodan.APIError as e:
            logger.error(f"Shodan search error: {e}")
            raise

    def get_api_info(self) -> Dict:
        """Get information about the API key."""
        if not self.api:
            raise RuntimeError("Shodan API client not initialized. Call set_api_key first.")
            
        self._rate_limit()
        try:
            return self.api.info()
        except shodan.APIError as e:
            logger.error(f"Error fetching API info: {e}")
            raise
