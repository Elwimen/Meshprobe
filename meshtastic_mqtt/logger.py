"""
JSON message logger for Meshtastic MQTT messages.
"""

import json
from pathlib import Path
from typing import Any
from dataclasses import asdict

from .models import ParsedMessage, TextMessage, PositionData, NodeInfo, DeviceTelemetry, EnvironmentTelemetry


class MessageLogger:
    """Logs Meshtastic messages to JSON file."""

    def __init__(self, log_file: str = "mqtt_messages.json"):
        """
        Initialize MessageLogger.

        Args:
            log_file: Path to JSON log file
        """
        self.log_file = Path(log_file)
        self.message_log: list[dict[str, Any]] = []

    def log_message(self, parsed_msg: ParsedMessage):
        """
        Log a parsed message to the JSON file.

        Args:
            parsed_msg: ParsedMessage to log
        """
        log_entry = self._convert_to_log_entry(parsed_msg)
        self.message_log.append(log_entry)
        self._write_to_file()

    def _convert_to_log_entry(self, parsed_msg: ParsedMessage) -> dict[str, Any]:
        """Convert ParsedMessage to JSON-serializable dictionary."""
        log_entry = {
            "timestamp": parsed_msg.timestamp,
            "topic": parsed_msg.topic,
            "channel_id": parsed_msg.channel_id,
            "gateway_id": parsed_msg.gateway_id,
            "packet": {
                "from": parsed_msg.packet_info.from_node_hex,
                "from_decimal": parsed_msg.packet_info.from_node,
                "to": parsed_msg.packet_info.to_node_hex,
                "to_decimal": parsed_msg.packet_info.to_node,
                "id": parsed_msg.packet_info.packet_id_hex,
                "id_decimal": parsed_msg.packet_info.packet_id,
                "channel_hash": parsed_msg.packet_info.channel_hash,
                "hop_limit": parsed_msg.packet_info.hop_limit,
                "hop_start": parsed_msg.packet_info.hop_start,
                "hops_away": parsed_msg.packet_info.hops_away,
                "via_mqtt": parsed_msg.packet_info.via_mqtt,
                "want_ack": parsed_msg.packet_info.want_ack,
            },
            "encrypted": parsed_msg.encrypted,
            "encrypted_payload_b64": parsed_msg.encrypted_payload_b64,
            "decoded_payload_b64": parsed_msg.decoded_payload_b64,
            "decoded": None
        }

        if parsed_msg.content:
            log_entry["decoded"] = {
                "portnum": parsed_msg.portnum,
                "portnum_name": parsed_msg.portnum_name,
                "content": self._serialize_content(parsed_msg.content)
            }

        return log_entry

    @staticmethod
    def _serialize_content(content) -> dict[str, Any]:
        """Serialize message content to JSON-serializable format."""
        match content:
            case TextMessage():
                return {
                    "type": "text",
                    "text": content.text,
                    "is_openssl_encrypted": content.is_openssl_encrypted
                }
            case PositionData():
                return {
                    "type": "position",
                    "latitude": content.latitude,
                    "longitude": content.longitude,
                    "altitude": content.altitude,
                    "time": content.time,
                    "precision_bits": content.precision_bits
                }
            case NodeInfo():
                return {
                    "type": "nodeinfo",
                    "id": content.node_id,
                    "long_name": content.long_name,
                    "short_name": content.short_name,
                    "macaddr": content.macaddr,
                    "hw_model": content.hw_model,
                    "hw_model_name": content.hw_model_name
                }
            case DeviceTelemetry():
                return {
                    "type": "telemetry",
                    "device_metrics": {
                        "battery_level": content.battery_level,
                        "voltage": content.voltage,
                        "channel_utilization": content.channel_utilization,
                        "air_util_tx": content.air_util_tx,
                        "uptime_seconds": content.uptime_seconds
                    }
                }
            case EnvironmentTelemetry():
                metrics = {}
                fields = ['temperature', 'relative_humidity', 'barometric_pressure', 'gas_resistance',
                         'voltage', 'current', 'iaq', 'distance', 'lux', 'white_lux', 'ir_lux', 'uv_lux',
                         'wind_direction', 'wind_speed', 'weight', 'wind_gust', 'wind_lull', 'radiation',
                         'rainfall_1h', 'rainfall_24h', 'soil_moisture', 'soil_temperature']
                for field in fields:
                    value = getattr(content, field, None)
                    if value is not None:
                        metrics[field] = value
                return {
                    "type": "telemetry",
                    "environment_metrics": metrics
                }
            case _:
                try:
                    return asdict(content)
                except Exception:
                    return {"type": "unknown"}

    def _write_to_file(self):
        """Write the message log to JSON file."""
        with open(self.log_file, 'w', encoding='utf-8') as f:
            json.dump(self.message_log, f, indent=2)

    def get_message_count(self) -> int:
        """Get the total number of logged messages."""
        return len(self.message_log)
