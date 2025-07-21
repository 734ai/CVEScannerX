"""Logging utility for CVEScannerX."""

import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict

def setup_logger(config: Dict) -> None:
    """Set up logging configuration."""
    log_config = config['logging']
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_config['output']['file'])
    os.makedirs(log_dir, exist_ok=True)
    
    # Create formatter
    formatter = logging.Formatter(log_config['format'])
    
    # Set up file handler
    file_handler = RotatingFileHandler(
        log_config['output']['file'],
        maxBytes=parse_size(log_config['output']['max_size']),
        backupCount=log_config['output']['backup_count']
    )
    file_handler.setFormatter(formatter)
    
    # Set up console handler if enabled
    handlers = [file_handler]
    if log_config['output']['console']:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, log_config['level'].upper()),
        handlers=handlers
    )

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the specified module."""
    return logging.getLogger(name)

def parse_size(size_str: str) -> int:
    """Parse size string (e.g., '10MB') to bytes."""
    units = {
        'B': 1,
        'KB': 1024,
        'MB': 1024 * 1024,
        'GB': 1024 * 1024 * 1024
    }
    
    size_str = size_str.upper()
    for unit, multiplier in units.items():
        if size_str.endswith(unit):
            try:
                number = float(size_str[:-len(unit)])
                return int(number * multiplier)
            except ValueError:
                raise ValueError(f"Invalid size format: {size_str}")
    
    raise ValueError(f"Invalid size unit in: {size_str}")
