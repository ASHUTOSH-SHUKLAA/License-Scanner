"""
Configuration module for the License Compliance Scanner.

This module provides centralized configuration management using environment variables.
"""

from config.settings import Settings, get_settings, load_settings, reload_settings

__all__ = ["Settings", "get_settings", "load_settings", "reload_settings"]
