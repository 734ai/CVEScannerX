"""Test parallel processing functionality."""

import pytest
from unittest.mock import Mock
from src.utils.parallel import run_parallel
import time

def test_run_parallel_empty_list():
    """Test parallel processing with empty list."""
    result = run_parallel(lambda x: x * 2, [])
    assert result == []

def test_run_parallel_single_item():
    """Test parallel processing with single item."""
    result = run_parallel(lambda x: x * 2, [1])
    assert result == [2]

def test_run_parallel_multiple_items():
    """Test parallel processing with multiple items."""
    result = run_parallel(lambda x: x * 2, [1, 2, 3, 4, 5])
    assert sorted(result) == [2, 4, 6, 8, 10]

def test_run_parallel_with_kwargs():
    """Test parallel processing with additional kwargs."""
    result = run_parallel(lambda x, y: x + y, [1, 2, 3], y=10)
    assert sorted(result) == [11, 12, 13]

def test_run_parallel_exception_handling():
    """Test parallel processing error handling."""
    def failing_func(x):
        if x == 2:
            raise ValueError("Test error")
        return x * 2
    
    result = run_parallel(failing_func, [1, 2, 3])
    assert sorted(result) == [2, 6]  # Result for x=2 should be skipped

def test_run_parallel_max_workers():
    """Test parallel processing respects max_workers."""
    def slow_func(x):
        time.sleep(0.1)
        return x * 2

    start_time = time.time()
    result = run_parallel(slow_func, [1, 2, 3, 4], max_workers=2)
    duration = time.time() - start_time

    assert sorted(result) == [2, 4, 6, 8]
    # With 4 items and max_workers=2, should take at least 0.2 seconds
    assert duration >= 0.2
