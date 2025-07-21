"""Rate limiter implementation for API clients."""

import time
from threading import Lock
from typing import Dict, Optional

class TokenBucket:
    """Token bucket algorithm implementation for rate limiting."""
    
    def __init__(self, rate: float, burst: int):
        """Initialize token bucket.
        
        Args:
            rate: Tokens per second
            burst: Maximum number of tokens (bucket size)
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            bool: True if tokens were consumed, False if not enough tokens
        """
        with self.lock:
            now = time.time()
            # Add new tokens based on time passed
            self.tokens = min(
                self.burst,
                self.tokens + (now - self.last_update) * self.rate
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

class RateLimiter:
    """Rate limiter for API clients."""
    
    def __init__(self):
        """Initialize rate limiter."""
        self.limiters: Dict[str, TokenBucket] = {}

    def add_limiter(self, name: str, rate: float, burst: int) -> None:
        """Add a new rate limiter.
        
        Args:
            name: Name of the limiter
            rate: Tokens per second
            burst: Maximum number of tokens
        """
        self.limiters[name] = TokenBucket(rate, burst)

    def wait(self, name: str, tokens: int = 1) -> None:
        """Wait until tokens are available.
        
        Args:
            name: Name of the limiter
            tokens: Number of tokens to consume
        """
        limiter = self.limiters.get(name)
        if not limiter:
            return
            
        while not limiter.consume(tokens):
            time.sleep(0.1)  # Wait 100ms before retrying
