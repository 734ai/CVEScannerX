"""Parallel processing utility for CVEScannerX."""

import concurrent.futures
from typing import List, Callable, TypeVar, Any
from functools import partial

T = TypeVar('T')

def run_parallel(func: Callable[..., T], items: List[Any], max_workers: int = None, **kwargs) -> List[T]:
    """Execute a function across multiple items in parallel.
    
    Args:
        func: Function to execute
        items: List of items to process
        max_workers: Maximum number of worker threads/processes
        **kwargs: Additional arguments to pass to the function
        
    Returns:
        List of results from parallel execution
    """
    if not items:
        return []
        
    # Create partial function with kwargs
    if kwargs:
        func = partial(func, **kwargs)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_item = {executor.submit(func, item): item for item in items}
        
        results = []
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                # Log error but continue processing other items
                from .logger import get_logger
                logger = get_logger(__name__)
                logger.error(f"Error processing {item}: {str(e)}")
                
    return results
