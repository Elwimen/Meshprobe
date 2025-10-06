"""
Meshtastic MQTT Client Package

A modular Python package for interacting with Meshtastic mesh networks via MQTT.
"""

from .client import MeshtasticMQTTClient
from .config import ServerConfig, NodeConfig, ClientConfig, Position, DeviceMetrics, EnvironmentMetrics
from .crypto import CryptoEngine
from .logger import MessageLogger
from .formatters import MessageFormatter
from .parsers import MessageParser
from .publishers import MessagePublisher
from .message_filter import MessageFilter
from .utils import parse_node_id, format_node_id_hex, is_json_payload, is_ascii_text, NodeIdParser, PayloadDetector
from .exceptions import MeshtasticError, ConfigError, NodeIdError, DecryptionError, DatabaseError, ConnectionError
from .hex_dump import HexDumper, hex_dump
from .logging_config import LoggingManager, setup_logging, get_logger
from .node_db import NodeDatabase

__all__ = [
    # Main client
    'MeshtasticMQTTClient',
    # Configuration
    'ServerConfig',
    'NodeConfig',
    'ClientConfig',
    'Position',
    'DeviceMetrics',
    'EnvironmentMetrics',
    # Core components
    'CryptoEngine',
    'MessageLogger',
    'MessageFormatter',
    'MessageParser',
    'MessagePublisher',
    'MessageFilter',
    'NodeDatabase',
    # Utilities
    'parse_node_id',
    'format_node_id_hex',
    'is_json_payload',
    'is_ascii_text',
    'NodeIdParser',
    'PayloadDetector',
    # Exceptions
    'MeshtasticError',
    'ConfigError',
    'NodeIdError',
    'DecryptionError',
    'DatabaseError',
    'ConnectionError',
    # Hex dump
    'HexDumper',
    'hex_dump',
    # Logging
    'LoggingManager',
    'setup_logging',
    'get_logger',
]

__version__ = '1.0.0'
