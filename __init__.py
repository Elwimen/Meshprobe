"""
Meshprobe - CLI toolkit for probing and interacting with Meshtastic networks over MQTT
"""

__version__ = "0.1.0"

# Re-export main function for module execution
from .meshprobe import main

__all__ = ['main']
