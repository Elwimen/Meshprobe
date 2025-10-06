"""
Custom exceptions for Meshtastic MQTT client.
"""


class MeshtasticError(Exception):
    """Base exception for all Meshtastic MQTT client errors."""
    pass


class ConfigError(MeshtasticError):
    """Exception raised for configuration errors."""
    pass


class NodeIdError(MeshtasticError):
    """Exception raised for node ID parsing or validation errors."""
    pass


class DecryptionError(MeshtasticError):
    """Exception raised for decryption failures."""
    pass


class DatabaseError(MeshtasticError):
    """Exception raised for node database errors."""
    pass


class ConnectionError(MeshtasticError):
    """Exception raised for MQTT connection errors."""
    pass
