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
from .utils import parse_node_id, format_node_id_hex, is_json_payload, is_ascii_text

__all__ = [
    'MeshtasticMQTTClient',
    'ServerConfig',
    'NodeConfig',
    'ClientConfig',
    'Position',
    'DeviceMetrics',
    'EnvironmentMetrics',
    'CryptoEngine',
    'MessageLogger',
    'MessageFormatter',
    'MessageParser',
    'MessagePublisher',
    'MessageFilter',
    'parse_node_id',
    'format_node_id_hex',
    'is_json_payload',
    'is_ascii_text',
]

__version__ = '1.0.0'
