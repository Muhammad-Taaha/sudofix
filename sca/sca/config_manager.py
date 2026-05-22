"""Configuration file parser and manager for SCA."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from sca.utils import get_logger

logger = get_logger(__name__)


DEFAULT_CONFIG = """
# Software Composition Analysis Configuration
# Place this as sca-config.yml in your project root or set SCA_CONFIG_FILE env var

# Cache settings
cache:
  directory: ~/.cache/sca
  ttl_days: 30

# File discovery settings
files:
  max_size_mb: 100
  skip_binary: true
  skip_minified: true
  ignore_patterns:
    - .git
    - __pycache__
    - node_modules
    - vendor
    - dist
    - build

# Scanning settings
scanning:
  timeout_per_file: 10
  max_parallel_workers: 4
  include_git_history: false

# Vulnerability settings
vulnerability:
  min_severity: MEDIUM
  min_cvss_score: 4.0
  offline_mode: false

# Logging settings
logging:
  level: INFO
  format: json  # or "text"

# License settings
license:
  detection_enabled: true
  require_attribution: true
  allowed_licenses: []
  forbidden_licenses:
    - GPL-3.0
    - AGPL-3.0

# Output settings
output:
  format: json  # json, html, spdx, vex
  report_file: sca-report.json
  html_template: default
"""


class SCAConfig:
    """Configuration manager for SCA."""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._find_config_file()
        self.data: Dict[str, Any] = {}
        
        if self.config_file and Path(self.config_file).exists():
            self._load_config()
        else:
            self._load_defaults()
    
    def _find_config_file(self) -> Optional[str]:
        """Search for config file in standard locations."""
        # Check environment variable first
        if env_config := os.environ.get("SCA_CONFIG_FILE"):
            return env_config
        
        # Check current directory and parent directories
        current = Path.cwd()
        for _ in range(5):  # Check up to 5 levels
            config_path = current / "sca-config.yml"
            if config_path.exists():
                return str(config_path)
            current = current.parent
        
        return None
    
    def _load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self.config_file, 'r') as f:
                self.data = yaml.safe_load(f) or {}
            logger.info(f"Loaded config from {self.config_file}")
        except Exception as e:
            logger.warning(f"Failed to load config from {self.config_file}: {e}")
            self._load_defaults()
    
    def _load_defaults(self):
        """Load default configuration."""
        self.data = yaml.safe_load(DEFAULT_CONFIG)
    
    def get(self, path: str, default: Any = None) -> Any:
        """Get config value by dot-notation path (e.g., 'cache.directory')."""
        keys = path.split('.')
        value = self.data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value
    
    def set(self, path: str, value: Any):
        """Set config value by dot-notation path."""
        keys = path.split('.')
        current = self.data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
    
    def merge_with_kwargs(self, **kwargs) -> Dict[str, Any]:
        """Merge config with CLI kwargs (kwargs override config)."""
        result = {}
        
        # Start with config values
        for key, val in self.data.items():
            result[key] = val
        
        # Override with kwargs
        for key, val in kwargs.items():
            if val is not None:
                result[key] = val
        
        return result
    
    @staticmethod
    def generate_default_config(output_file: str = "sca-config.yml"):
        """Generate a default configuration file."""
        Path(output_file).write_text(DEFAULT_CONFIG)
        logger.info(f"Default configuration written to {output_file}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self.data
