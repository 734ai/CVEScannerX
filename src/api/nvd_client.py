"""NVD API client for CVEScannerX."""

import time
import requests
from typing import Dict, Optional
from ..utils.logger import get_logger

logger = get_logger(__name__)

class NVDClient:
    """Client for the National Vulnerability Database (NVD) API."""
    
    def __init__(self, config: Dict):
        """Initialize NVD API client."""
        self.config = config['api_config']['nvd']
        self.base_url = self.config['base_url']
        self.version = self.config['version']
        self.api_key = None
        self.last_request_time = 0
        self.min_request_interval = 1.0 / self.config['rate_limit']['requests_per_second']

    def set_api_key(self, api_key: str) -> None:
        """Set the API key for NVD API access."""
        self.api_key = api_key

    def _rate_limit(self) -> None:
        """Implement rate limiting for API requests."""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def get_cve(self, cve_id: str) -> Dict:
        """Fetch details for a specific CVE."""
        self._rate_limit()
        
        url = f"{self.base_url}/cves/{self.version}"
        params = {'cveId': cve_id}
        headers = {}
        
        if self.api_key:
            headers['apiKey'] = self.api_key
            
        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            raise

    def search_cves(self, 
                   keyword: Optional[str] = None,
                   cpe_name: Optional[str] = None,
                   published_from: Optional[str] = None,
                   published_to: Optional[str] = None) -> Dict:
        """Search for CVEs using various criteria."""
        self._rate_limit()
        
        url = f"{self.base_url}/cves/{self.version}"
        params = {}
        headers = {}
        
        if keyword:
            params['keywordSearch'] = keyword
        if cpe_name:
            params['cpeName'] = cpe_name
        if published_from:
            params['pubStartDate'] = published_from
        if published_to:
            params['pubEndDate'] = published_to
            
        if self.api_key:
            headers['apiKey'] = self.api_key
            
        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"Error searching CVEs: {e}")
            raise
