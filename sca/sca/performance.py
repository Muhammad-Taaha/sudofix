"""Performance profiling and optimization utilities."""

from __future__ import annotations

import cProfile
import io
import pstats
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sca.utils import get_logger

logger = get_logger(__name__)


class PerformanceProfiler:
    """Context manager for profiling code sections."""
    
    def __init__(self, name: str = "profile", output_file: Optional[str] = None):
        self.name = name
        self.output_file = output_file
        self.profiler: Optional[cProfile.Profile] = None
        self.start_time: float = 0
        self.elapsed: float = 0
    
    def __enter__(self):
        self.start_time = time.time()
        self.profiler = cProfile.Profile()
        self.profiler.enable()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.profiler.disable()
        self.elapsed = time.time() - self.start_time
        
        logger.info(f"Performance profile '{self.name}'", elapsed_seconds=self.elapsed)
        
        if self.output_file:
            self.profiler.dump_stats(self.output_file)
            logger.info(f"Profile stats saved to {self.output_file}")
        
        # Print top functions
        s = io.StringIO()
        ps = pstats.Stats(self.profiler, stream=s).sort_stats('cumulative')
        ps.print_stats(10)
        logger.debug(f"Top 10 functions:\n{s.getvalue()}")


@contextmanager
def timer(name: str):
    """Simple timer context manager."""
    start = time.time()
    try:
        yield
    finally:
        elapsed = time.time() - start
        logger.info(f"Timing '{name}'", elapsed_seconds=elapsed)


def profile_function(func: Callable) -> Callable:
    """Decorator to profile a function."""
    def wrapper(*args, **kwargs):
        with PerformanceProfiler(name=func.__name__):
            return func(*args, **kwargs)
    return wrapper


class PerformanceBenchmark:
    """Collect and report performance metrics."""
    
    def __init__(self):
        self.metrics: Dict[str, list] = {}
    
    def record(self, name: str, value: float, unit: str = "seconds"):
        """Record a metric."""
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append({"value": value, "unit": unit})
    
    def summary(self) -> str:
        """Get summary report."""
        lines = ["Performance Benchmark Summary", "=" * 50]
        for name, values in self.metrics.items():
            avg = sum(v["value"] for v in values) / len(values) if values else 0
            unit = values[0]["unit"] if values else "?"
            lines.append(f"{name}: avg={avg:.2f}{unit}, samples={len(values)}")
        return "\n".join(lines)
    
    def save(self, output_file: str):
        """Save benchmark results to file."""
        Path(output_file).write_text(self.summary())
        logger.info(f"Benchmark results saved to {output_file}")


# Global benchmark instance
_benchmark = PerformanceBenchmark()


def get_benchmark() -> PerformanceBenchmark:
    """Get the global benchmark instance."""
    return _benchmark
