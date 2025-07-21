"""SecurityTrails API client for CVEScannerX."""

import time
import requests
from typing import Dict, List, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class SecurityTrailsClient:
    """Client for the SecurityTrails API."""
    
    def __init__(self, config: Dict):
        """Initialize SecurityTrails API client."""
        self.config = config['api_config']['securitytrails']
        self.base_url = self.config['base_url']
        self.api_key = None
        self.last_request_time = 0
        self.min_request_interval = 1.0 / self.config['rate_limit']['requests_per_second']

    def set_api_key(self, api_key: str) -> None:
        """Set the API key for SecurityTrails API access."""
        self.api_key = api_key

    def _rate_limit(self) -> None:
        """Implement rate limiting for API requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make an API request with proper headers and error handling."""
        if not self.api_key:
            raise RuntimeError("API key not set. Call set_api_key first.")
            
        self._rate_limit()
        
        headers = {
            'APIKEY': self.api_key,
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"SecurityTrails API error: {e}")
            raise

    def domain_info(self, domain: str) -> Dict:
        """Get general information about a domain."""
        return self._make_request(f"domain/{domain}")

    def get_subdomains(self, domain: str) -> List[str]:
        """Get a list of subdomains for a domain."""
        response = self._make_request(f"domain/{domain}/subdomains")
        return response.get('subdomains', [])

    def get_whois(self, domain: str) -> Dict:
        """Get WHOIS information for a domain."""
        return self._make_request(f"domain/{domain}/whois")

    def get_history(self, domain: str, record_type: str = 'a') -> Dict:
        """Get historical DNS records for a domain."""
        return self._make_request(
            f"history/{domain}/dns/{record_type}"
        )

    def get_associated_ips(self, domain: str) -> Dict:
        """Get IPs associated with a domain."""
        return self._make_request(f"domain/{domain}/stats")
