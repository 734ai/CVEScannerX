"""Progress indicator context manager for CVEScannerX."""

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

class ScanProgress:
    """Context manager for scan progress indication."""
    
    def __init__(self, description: str = "Scanning"):
        """Initialize progress indicator."""
        self.description = description
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
        )
        self.task_id = None

    def __enter__(self):
        """Start progress indication."""
        self.progress.start()
        self.task_id = self.progress.add_task(self.description, total=None)
        return self.progress

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop progress indication."""
        self.progress.stop()
