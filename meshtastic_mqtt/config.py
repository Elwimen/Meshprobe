"""
Configuration dataclasses for Meshtastic MQTT client.
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _extract_value(data: dict | str | int, key: str, default):
    """Extract value from dict with 'value' key or return raw data."""
    field_data = data.get(key, default) if isinstance(data, dict) else data
    if isinstance(field_data, dict):
        return field_data.get('value', default)
    return field_data if field_data is not None else default


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
    """Node configuration with computed node_num from node_id."""
    node_id: str
    long_name: str = "Simulated Node"
    short_name: str = "SIM"
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

    def __post_init__(self):
        """Calculate node_num from node_id if it starts with !"""
        if self.node_id.startswith('!'):
            self.node_num = int(self.node_id[1:], 16)
        else:
            raise ValueError("node_id must start with ! prefix")

        if isinstance(self.position, dict):
            position_data = {k: v for k, v in self.position.items() if not k.startswith('_')}
            self.position = Position(**position_data)

        if isinstance(self.device_metrics, dict):
            metrics_data = {k: v for k, v in self.device_metrics.items() if not k.startswith('_')}
            self.device_metrics = DeviceMetrics(**metrics_data)

        if isinstance(self.environment_metrics, dict):
            env_data = {k: v for k, v in self.environment_metrics.items() if not k.startswith('_')}
            self.environment_metrics = EnvironmentMetrics(**env_data)

    @classmethod
    def from_json(cls, path: str | Path) -> 'NodeConfig':
        """Load NodeConfig from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)

            node_id_data = data.get('node_id', {})
            node_id = node_id_data.get('id', '') if isinstance(node_id_data, dict) else node_id_data

            channel_data = data.get('channel', data.get('channel_id', {}))
            channel = _extract_value(channel_data, 'value', 'LongFast')

            hw_model = _extract_value(data, 'hw_model', 0)
            role = _extract_value(data, 'role', 0)
            region = _extract_value(data, 'region', 'UNSET')
            modem_preset = _extract_value(data, 'modem_preset', 'LONG_FAST')

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
                channels=data.get('channels', {}),
            )
        except FileNotFoundError:
            print(f"Error: Config file not found: {path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {path}: {e}")
            sys.exit(1)


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
            with open(path, 'r') as f:
                data = json.load(f)
            return cls(**data)
        except FileNotFoundError:
            print(f"Error: Config file not found: {path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {path}: {e}")
            sys.exit(1)


def create_default_configs(server_path: str = "server_config.json",
                          node_path: str = "node_config.json") -> None:
    """Create default configuration files if they don't exist."""
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
            "_comment": "Node ID with ! prefix (num is calculated automatically)"
        },
        "channel": {
            "value": "LongFast",
            "_comment": "Channel name"
        },
        "long_name": "Simulated Node",
        "short_name": "SIM",
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

    server_path_obj = Path(server_path)
    node_path_obj = Path(node_path)

    if not server_path_obj.exists():
        with open(server_path_obj, 'w') as f:
            json.dump(server_config, f, indent=2)
        print(f"Created default server config: {server_path}")

    if not node_path_obj.exists():
        with open(node_path_obj, 'w') as f:
            json.dump(node_config, f, indent=2)
        print(f"Created default node config: {node_path}")
