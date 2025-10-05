"""
Data models for Meshtastic messages.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class PacketInfo:
    """Information about a Meshtastic packet."""
    from_node: int
    from_node_hex: str
    to_node: int
    to_node_hex: str
    packet_id: int
    packet_id_hex: str
    channel_hash: int
    hop_limit: int
    hop_start: int
    hops_away: int
    via_mqtt: bool
    want_ack: bool


@dataclass
class TextMessage:
    """Text message content."""
    text: str
    is_openssl_encrypted: bool = False
    is_salted_base64: bool | None = None
    decrypted: bool = False


@dataclass
class PositionData:
    """Position information."""
    latitude: float
    longitude: float
    altitude: int
    time: Optional[int] = None
    precision_bits: Optional[int] = None


@dataclass
class NodeInfo:
    """Node information."""
    node_id: Optional[str] = None
    long_name: Optional[str] = None
    short_name: Optional[str] = None
    macaddr: Optional[str] = None
    hw_model: Optional[int] = None
    hw_model_name: Optional[str] = None


@dataclass
class DeviceTelemetry:
    """Device telemetry metrics."""
    battery_level: Optional[int] = None
    voltage: Optional[float] = None
    channel_utilization: Optional[float] = None
    air_util_tx: Optional[float] = None
    uptime_seconds: Optional[int] = None


@dataclass
class EnvironmentTelemetry:
    """Environment telemetry metrics."""
    temperature: Optional[float] = None
    relative_humidity: Optional[float] = None
    barometric_pressure: Optional[float] = None
    gas_resistance: Optional[float] = None
    voltage: Optional[float] = None
    current: Optional[float] = None
    iaq: Optional[int] = None
    distance: Optional[float] = None
    lux: Optional[float] = None
    white_lux: Optional[float] = None
    ir_lux: Optional[float] = None
    uv_lux: Optional[float] = None
    wind_direction: Optional[int] = None
    wind_speed: Optional[float] = None
    weight: Optional[float] = None
    wind_gust: Optional[float] = None
    wind_lull: Optional[float] = None
    radiation: Optional[float] = None
    rainfall_1h: Optional[float] = None
    rainfall_24h: Optional[float] = None
    soil_moisture: Optional[float] = None
    soil_temperature: Optional[float] = None


@dataclass
class RoutingInfo:
    """Routing message information."""
    error_reason: str = "ACK"


@dataclass
class NeighborData:
    """Neighbor node information."""
    node_id: int
    node_id_hex: str
    snr: float


@dataclass
class NeighborInfo:
    """Neighbor info message."""
    reporter_node_id: int
    reporter_node_hex: str
    via_node_id: Optional[int] = None
    via_node_hex: Optional[str] = None
    broadcast_interval_secs: int = 0
    neighbors: list[NeighborData] = field(default_factory=list)


@dataclass
class MapReport:
    """Map report information."""
    long_name: str
    short_name: str
    latitude: float
    longitude: float
    altitude: int
    firmware_version: str
    region: Optional[str] = None
    modem_preset: Optional[str] = None


@dataclass
class ParsedMessage:
    """
    Parsed Meshtastic message with all information.
    """
    timestamp: str
    topic: str
    channel_id: str
    gateway_id: str
    packet_info: PacketInfo
    portnum: int
    portnum_name: str
    encrypted: bool
    content: Optional[
        TextMessage | PositionData | NodeInfo | DeviceTelemetry |
        EnvironmentTelemetry | RoutingInfo | NeighborInfo | MapReport
    ] = None
    encrypted_payload_b64: Optional[str] = None
    decoded_payload_b64: Optional[str] = None
    raw_service_envelope: Optional[bytes] = None


@dataclass
class Statistics:
    """MQTT client statistics."""
    total_messages: int = 0
    successful_decrypts: int = 0
    failed_decrypts: int = 0
    parse_errors: int = 0
    portnum_counts: dict[str, int] = field(default_factory=dict)

    def increment_portnum(self, portnum_name: str):
        """Increment counter for a specific portnum."""
        self.portnum_counts[portnum_name] = self.portnum_counts.get(portnum_name, 0) + 1

    def get_sorted_portnums(self) -> list[tuple[str, int]]:
        """Get portnum counts sorted by frequency."""
        return sorted(self.portnum_counts.items(), key=lambda x: x[1], reverse=True)
