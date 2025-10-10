"""
Configuration dataclasses for Meshtastic MQTT client.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .exceptions import ConfigError


@dataclass
class Position:
    """Node position configuration."""
    latitude: float = 37.4127
    longitude: float = -122.0627
    altitude: int = 100
    precision: int = 14


@dataclass
class DeviceMetrics:
    """Device telemetry metrics."""
    battery_level: int = 100
    voltage: float = 4.2
    channel_utilization: float = 0.0
    air_util_tx: float = 0.0
    uptime_seconds: int = 0


@dataclass
class EnvironmentMetrics:
    """Environment telemetry metrics."""
    temperature: float = 0.0
    relative_humidity: float = 0.0
    barometric_pressure: float = 0.0
    gas_resistance: float = 0.0
    voltage: float = 0.0
    current: float = 0.0
    iaq: int = 0
    distance: float = 0.0
    lux: float = 0.0
    white_lux: float = 0.0
    ir_lux: float = 0.0
    uv_lux: float = 0.0
    wind_direction: int = 0
    wind_speed: float = 0.0
    weight: float = 0.0
    wind_gust: float = 0.0
    wind_lull: float = 0.0
    radiation: float = 0.0
    rainfall_1h: float = 0.0
    rainfall_24h: float = 0.0
    soil_moisture: int = 0
    soil_temperature: float = 0.0


@dataclass
class NodeConfig:
    """
    Node configuration with computed node_num from node_id.

    Node ID Format and Constraints:
    --------------------------------
    Node IDs are transmitted as ASCII strings in the Meshtastic protocol,
    not as binary integers. This uses more bandwidth but provides flexibility.

    Size Limit: 16 bytes maximum (defined in mesh.options: *id max_size:16)

    Common Formats:
    - MAC-derived (default): !1337b4b3 (10 bytes: ! + 8 hex chars + null)
    - Phone numbers: +16504442323 (12-13 bytes)
    - Special IDs: ^all (broadcast), ^local (locally connected node) (4-6 bytes)

    Bandwidth Cost:
    - ASCII: !1337b4b3 = 9 bytes (21 31 33 33 37 62 34 62 33 in hex)
    - Binary equivalent would be 4 bytes (13 37 b4 b3)

    Trade-off: Uses >2x bandwidth for flexibility, human readability, and
    support for multiple ID formats (MAC addresses, phone numbers, special IDs).

    Note: The node_num field is automatically computed from node_id if it
    starts with ! prefix (converts hex string to uint32).
    """
    node_id: str  # Max 16 bytes, see docstring for format details
    long_name: str = "Simulated Node"  # Max 40 bytes (mesh.options)
    short_name: str = "SIM"  # Max 5 bytes (mesh.options)
    channel: str = "LongFast"
    position: Position = field(default_factory=Position)
    device_metrics: DeviceMetrics = field(default_factory=DeviceMetrics)
    environment_metrics: EnvironmentMetrics = field(default_factory=EnvironmentMetrics)
    hw_model: int = 0
    role: int = 0
    firmware_version: str = "2.5.0.simulated"
    region: str = "UNSET"
    modem_preset: str = "LONG_FAST"
    has_default_channel: bool = True
    channels: dict = field(default_factory=dict)
    channel_map: dict = field(default_factory=dict)  # Maps channel index to name

    @staticmethod
    def _extract_value(data: dict | str | int, key: str, default):
        """Extract value from dict with 'value' key or return raw data."""
        field_data = data.get(key, default) if isinstance(data, dict) else data
        if isinstance(field_data, dict):
            return field_data.get('value', default)
        return field_data if field_data is not None else default

    def __post_init__(self):
        """Calculate node_num from node_id and validate."""
        from .utils import parse_node_id

        # Validate and parse node_id
        if not self.node_id.startswith('!'):
            raise ValueError(
                f"node_id must start with ! prefix in config. Got: '{self.node_id}'. "
                f"Example: !1337b4b3"
            )

        try:
            self.node_num = parse_node_id(self.node_id)
        except ValueError as e:
            raise ValueError(f"Invalid node_id in config: {e}") from e

        if isinstance(self.position, dict):
            position_data = {k: v for k, v in self.position.items() if not k.startswith('_')}
            self.position = Position(**position_data)

        if isinstance(self.device_metrics, dict):
            metrics_data = {k: v for k, v in self.device_metrics.items() if not k.startswith('_')}
            self.device_metrics = DeviceMetrics(**metrics_data)

        if isinstance(self.environment_metrics, dict):
            env_data = {k: v for k, v in self.environment_metrics.items() if not k.startswith('_')}
            self.environment_metrics = EnvironmentMetrics(**env_data)

    def get_channel_name(self, channel_index: int) -> str:
        """
        Get channel name from channel index.

        Args:
            channel_index: Channel index (0-based)

        Returns:
            Channel name, or default channel if not found
        """
        return self.channel_map.get(str(channel_index), self.channel)

    @classmethod
    def from_json(cls, path: str | Path) -> 'NodeConfig':
        """Load NodeConfig from JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            node_id_data = data.get('node_id', {})
            node_id = node_id_data.get('id', '') if isinstance(node_id_data, dict) else node_id_data

            channel_data = data.get('channel', data.get('channel_id', {}))
            channel = NodeConfig._extract_value(channel_data, 'value', 'LongFast')

            hw_model = NodeConfig._extract_value(data, 'hw_model', 0)
            role = NodeConfig._extract_value(data, 'role', 0)
            region = NodeConfig._extract_value(data, 'region', 'UNSET')
            modem_preset = NodeConfig._extract_value(data, 'modem_preset', 'LONG_FAST')

            # Parse channel_map if available
            channel_map = {}
            channels_data = data.get('channels', {})
            for key, value in channels_data.items():
                # Support both old format {"LongFast": {"psk": "..."}}
                # and new format {"0": {"name": "LongFast", "psk": "..."}}
                if key.isdigit():
                    if isinstance(value, dict) and 'name' in value:
                        channel_map[key] = value['name']

            return cls(
                node_id=node_id,
                long_name=data.get('long_name', 'Simulated Node'),
                short_name=data.get('short_name', 'SIM'),
                channel=channel,
                position=data.get('position', {}),
                device_metrics=data.get('device_metrics', {}),
                environment_metrics=data.get('environment_metrics', {}),
                hw_model=hw_model,
                role=role,
                firmware_version=data.get('firmware_version', '2.5.0.simulated'),
                region=region,
                modem_preset=modem_preset,
                has_default_channel=data.get('has_default_channel', True),
                channels=channels_data,
                channel_map=channel_map,
            )
        except FileNotFoundError as e:
            raise ConfigError(f"Config file not found: {path}") from e
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {path}: {e}") from e


@dataclass
class ClientConfig:
    """Client configuration."""
    node_db_flush_interval: int = 5  # seconds
    nodes_dir: str = "nodes"

    @classmethod
    def from_json(cls, path: str | Path) -> 'ClientConfig':
        """Load ClientConfig from JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if not k.startswith('_')})
        except FileNotFoundError:
            # Return default config if file doesn't exist
            return cls()
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {path}: {e}") from e


@dataclass
class ServerConfig:
    """MQTT server configuration."""
    host: str = "mqtt.meshtastic.org"
    port: int = 1883
    username: str = "meshdev"
    password: str = "large4cats"
    root_topic: str = "msh"

    @classmethod
    def from_json(cls, path: str | Path) -> 'ServerConfig':
        """Load ServerConfig from JSON file."""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls(**data)
        except FileNotFoundError as e:
            raise ConfigError(f"Config file not found: {path}") from e
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {path}: {e}") from e


def create_default_configs(server_path: str = "server_config.json",
                          node_path: str = "node_config.json",
                          client_path: str = "client_config.json") -> None:
    """Create default configuration files if they don't exist."""
    client_config = {
        "node_db_flush_interval": 5,
        "_comment": "Flush interval in seconds for node database writes",
        "nodes_dir": "nodes"
    }

    server_config = {
        "host": "mqtt.meshtastic.org",
        "port": 1883,
        "username": "meshdev",
        "password": "large4cats",
        "root_topic": "msh"
    }

    node_config = {
        "node_id": {
            "id": "!12345678",
            "_comment": "Node ID with ! prefix (num is calculated automatically). Max 16 bytes. Format: !<8 hex chars> for MAC-derived, +<phone> for phone numbers, or ^all/^local for special IDs. Transmitted as ASCII string in protobuf."
        },
        "channel": {
            "value": "LongFast",
            "_comment": "Channel name"
        },
        "long_name": "Simulated Node",
        "_long_name_comment": "Max 40 bytes (mesh.options)",
        "short_name": "SIM",
        "_short_name_comment": "Max 5 bytes, ideally 2 characters for tiny OLED screens (mesh.options)",
        "hw_model": {
            "value": 0,
            "_comment": {}
        },
        "role": {
            "value": 0,
            "_comment": {}
        },
        "firmware_version": "2.5.0.simulated",
        "region": {
            "value": "UNSET",
            "_comment": {}
        },
        "modem_preset": {
            "value": "LONG_FAST",
            "_comment": "Modem preset"
        },
        "has_default_channel": True,
        "position": {
            "latitude": 37.4127,
            "longitude": -122.0627,
            "altitude": 100,
            "precision": 14,
            "_comment": "Position precision bits (12-15, default 14)"
        },
        "device_metrics": {
            "battery_level": 100,
            "voltage": 4.2,
            "channel_utilization": 0.0,
            "air_util_tx": 0.0,
            "uptime_seconds": 0,
            "_comment": "Battery level 0-100, or 101 for plugged in"
        }
    }

    client_path_obj = Path(client_path)
    server_path_obj = Path(server_path)
    node_path_obj = Path(node_path)

    if not client_path_obj.exists():
        with open(client_path_obj, 'w', encoding='utf-8') as f:
            json.dump(client_config, f, indent=2)
        print(f"Created default client config: {client_path}")

    if not server_path_obj.exists():
        with open(server_path_obj, 'w', encoding='utf-8') as f:
            json.dump(server_config, f, indent=2)
        print(f"Created default server config: {server_path}")

    if not node_path_obj.exists():
        with open(node_path_obj, 'w', encoding='utf-8') as f:
            json.dump(node_config, f, indent=2)
        print(f"Created default node config: {node_path}")
