"""
Message parsers for Meshtastic protobuf messages.
"""

import base64
from datetime import datetime, timezone
from typing import Optional

try:
    from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, config_pb2, telemetry_pb2
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic")
    import sys
    sys.exit(1)

from .models import (
    PacketInfo, TextMessage, PositionData, NodeInfo,
    DeviceTelemetry, EnvironmentTelemetry, RoutingInfo,
    NeighborInfo, NeighborData, MapReport, ParsedMessage
)
from .node_db import NodeDatabase


class MessageParser:
    """Parser for Meshtastic protobuf messages."""

    def __init__(self, node_db: Optional[NodeDatabase] = None):
        """
        Initialize MessageParser.

        Args:
            node_db: Optional NodeDatabase to populate with node info
        """
        self.node_db = node_db

    @staticmethod
    def parse_packet_info(packet) -> PacketInfo:
        """Extract packet metadata into PacketInfo dataclass."""
        from_node = getattr(packet, 'from')
        to_node = packet.to
        hop_limit = packet.hop_limit if hasattr(packet, 'hop_limit') else 0
        hop_start = packet.hop_start if hasattr(packet, 'hop_start') else 0

        return PacketInfo(
            from_node=from_node,
            from_node_hex=f"!{from_node:08x}",
            to_node=to_node,
            to_node_hex=f"!{to_node:08x}",
            packet_id=packet.id,
            packet_id_hex=f"0x{packet.id:08x}",
            channel_hash=packet.channel if hasattr(packet, 'channel') else 0,
            hop_limit=hop_limit,
            hop_start=hop_start,
            hops_away=hop_start - hop_limit if hop_start > 0 else 0,
            via_mqtt=packet.via_mqtt if hasattr(packet, 'via_mqtt') else False,
            want_ack=packet.want_ack if hasattr(packet, 'want_ack') else False,
        )

    def parse_message_content(self, portnum: int, payload: bytes, from_node_hex: str = None, to_node_hex: str = None) -> Optional[
        TextMessage | PositionData | NodeInfo | DeviceTelemetry |
        EnvironmentTelemetry | RoutingInfo | NeighborInfo | MapReport
    ]:
        """
        Parse message payload based on portnum.
        Uses minimal nesting with early returns.
        """
        match portnum:
            case portnums_pb2.TEXT_MESSAGE_APP:
                return self._parse_text_message(payload, from_node_hex, to_node_hex)
            case portnums_pb2.POSITION_APP:
                return self._parse_position(payload, from_node_hex)
            case portnums_pb2.NODEINFO_APP:
                return self._parse_nodeinfo(payload)
            case portnums_pb2.TELEMETRY_APP:
                return self._parse_telemetry(payload, from_node_hex)
            case portnums_pb2.ROUTING_APP:
                return self._parse_routing(payload)
            case portnums_pb2.NEIGHBORINFO_APP:
                return self._parse_neighborinfo(payload)
            case portnums_pb2.MAP_REPORT_APP:
                return self._parse_map_report(payload, from_node_hex)
            case _:
                return None

    def _parse_text_message(self, payload: bytes, from_node_hex: str = None, to_node_hex: str = None) -> TextMessage:
        """Parse text message payload."""
        text = payload.decode('utf-8', errors='replace')
        is_encrypted = text.startswith('U2FsdGVk')

        # Log message to sender's node database
        if self.node_db is not None and from_node_hex:
            self.node_db.add_message(
                node_id=from_node_hex,
                text=text,
                direction='sent',
                encrypted=is_encrypted,
                from_node=from_node_hex,
                to_node=to_node_hex
            )

        # Log message to receiver's node database (if not broadcast)
        if self.node_db is not None and to_node_hex and to_node_hex != '!ffffffff':
            self.node_db.add_message(
                node_id=to_node_hex,
                text=text,
                direction='received',
                encrypted=is_encrypted,
                from_node=from_node_hex,
                to_node=to_node_hex
            )

        return TextMessage(text=text, is_openssl_encrypted=is_encrypted)

    def _parse_position(self, payload: bytes, from_node_hex: str = None) -> Optional[PositionData]:
        """Parse position payload."""
        try:
            position = mesh_pb2.Position()
            position.ParseFromString(payload)

            pos_data = PositionData(
                latitude=position.latitude_i / 1e7,
                longitude=position.longitude_i / 1e7,
                altitude=position.altitude,
                time=position.time if position.time else None,
                precision_bits=position.precision_bits if hasattr(position, 'precision_bits') else None
            )

            # Add to node database if available
            if self.node_db is not None and from_node_hex:
                self.node_db.add_position(
                    node_id=from_node_hex,
                    latitude=pos_data.latitude,
                    longitude=pos_data.longitude,
                    altitude=pos_data.altitude,
                    timestamp=pos_data.time
                )

            return pos_data
        except Exception:
            return None

    def _parse_nodeinfo(self, payload: bytes) -> Optional[NodeInfo]:
        """Parse node info payload."""
        try:
            user = mesh_pb2.User()
            user.ParseFromString(payload)

            hw_model_name = None
            if user.hw_model:
                try:
                    hw_model_name = config_pb2.Config.DeviceConfig.HardwareModel.Name(user.hw_model)
                except Exception:
                    pass

            macaddr = None
            if user.macaddr:
                macaddr = ':'.join(f'{b:02X}' for b in user.macaddr)

            node_info = NodeInfo(
                node_id=user.id if user.id else None,
                long_name=user.long_name if user.long_name else None,
                short_name=user.short_name if user.short_name else None,
                macaddr=macaddr,
                hw_model=user.hw_model if user.hw_model else None,
                hw_model_name=hw_model_name
            )

            # Add to node database if available
            if self.node_db is not None and node_info.node_id:
                self.node_db.add_node(
                    node_id=node_info.node_id,
                    long_name=node_info.long_name,
                    short_name=node_info.short_name,
                    hw_model=node_info.hw_model,
                    macaddr=macaddr
                )

            return node_info
        except Exception:
            return None

    def _parse_telemetry(self, payload: bytes, from_node_hex: str = None) -> Optional[DeviceTelemetry | EnvironmentTelemetry]:
        """Parse telemetry payload."""
        try:
            telemetry = telemetry_pb2.Telemetry()
            telemetry.ParseFromString(payload)

            if telemetry.HasField('device_metrics'):
                dm = telemetry.device_metrics
                device_telem = DeviceTelemetry(
                    battery_level=dm.battery_level if dm.battery_level else None,
                    voltage=dm.voltage if dm.voltage else None,
                    channel_utilization=dm.channel_utilization if dm.channel_utilization else None,
                    air_util_tx=dm.air_util_tx if dm.air_util_tx else None,
                    uptime_seconds=dm.uptime_seconds if dm.uptime_seconds else None
                )

                # Add to node database if available
                if self.node_db is not None and from_node_hex:
                    self.node_db.add_device_metrics(
                        node_id=from_node_hex,
                        battery_level=device_telem.battery_level,
                        voltage=device_telem.voltage,
                        channel_utilization=device_telem.channel_utilization,
                        air_util_tx=device_telem.air_util_tx,
                        uptime_seconds=device_telem.uptime_seconds
                    )

                return device_telem

            if telemetry.HasField('environment_metrics'):
                em = telemetry.environment_metrics
                env_telem = EnvironmentTelemetry(
                    temperature=em.temperature if em.temperature else None,
                    relative_humidity=em.relative_humidity if em.relative_humidity else None,
                    barometric_pressure=em.barometric_pressure if em.barometric_pressure else None,
                    gas_resistance=em.gas_resistance if em.gas_resistance else None,
                    voltage=em.voltage if em.voltage else None,
                    current=em.current if em.current else None,
                    iaq=em.iaq if em.iaq else None,
                    distance=em.distance if em.distance else None,
                    lux=em.lux if em.lux else None,
                    white_lux=em.white_lux if em.white_lux else None,
                    ir_lux=em.ir_lux if em.ir_lux else None,
                    uv_lux=em.uv_lux if em.uv_lux else None,
                    wind_direction=em.wind_direction if em.wind_direction else None,
                    wind_speed=em.wind_speed if em.wind_speed else None,
                    weight=em.weight if em.weight else None,
                    wind_gust=em.wind_gust if em.wind_gust else None,
                    wind_lull=em.wind_lull if em.wind_lull else None,
                    radiation=em.radiation if em.radiation else None,
                    rainfall_1h=em.rainfall_1h if em.rainfall_1h else None,
                    rainfall_24h=em.rainfall_24h if em.rainfall_24h else None,
                    soil_moisture=em.soil_moisture if em.soil_moisture else None,
                    soil_temperature=em.soil_temperature if em.soil_temperature else None
                )

                # Add to node database if available
                if self.node_db is not None and from_node_hex:
                    metrics = {}
                    fields = ['temperature', 'relative_humidity', 'barometric_pressure', 'gas_resistance',
                             'voltage', 'current', 'iaq', 'distance', 'lux', 'white_lux', 'ir_lux', 'uv_lux',
                             'wind_direction', 'wind_speed', 'weight', 'wind_gust', 'wind_lull', 'radiation',
                             'rainfall_1h', 'rainfall_24h', 'soil_moisture', 'soil_temperature']
                    for field in fields:
                        value = getattr(env_telem, field, None)
                        if value is not None:
                            metrics[field] = value

                    self.node_db.add_environment_metrics(node_id=from_node_hex, **metrics)

                return env_telem

            return None
        except Exception:
            return None

    @staticmethod
    def _parse_routing(payload: bytes) -> Optional[RoutingInfo]:
        """Parse routing payload."""
        try:
            routing = mesh_pb2.Routing()
            routing.ParseFromString(payload)
            error_reason = mesh_pb2.Routing.Error.Name(routing.error_reason) if routing.error_reason else "ACK"
            return RoutingInfo(error_reason=error_reason)
        except Exception:
            return None

    @staticmethod
    def _parse_neighborinfo(payload: bytes) -> Optional[NeighborInfo]:
        """Parse neighbor info payload."""
        try:
            neighbor_info = mesh_pb2.NeighborInfo()
            neighbor_info.ParseFromString(payload)

            neighbors = []
            for nbr in neighbor_info.neighbors:
                neighbors.append(NeighborData(
                    node_id=nbr.node_id,
                    node_id_hex=f"!{nbr.node_id:08x}",
                    snr=nbr.snr
                ))

            via_node_id = None
            via_node_hex = None
            if neighbor_info.last_sent_by_id != neighbor_info.node_id:
                via_node_id = neighbor_info.last_sent_by_id
                via_node_hex = f"!{via_node_id:08x}"

            return NeighborInfo(
                reporter_node_id=neighbor_info.node_id,
                reporter_node_hex=f"!{neighbor_info.node_id:08x}",
                via_node_id=via_node_id,
                via_node_hex=via_node_hex,
                broadcast_interval_secs=neighbor_info.node_broadcast_interval_secs,
                neighbors=neighbors
            )
        except Exception:
            return None

    def _parse_map_report(self, payload: bytes, from_node_hex: str = None) -> Optional[MapReport]:
        """Parse map report payload."""
        try:
            map_report = mqtt_pb2.MapReport()
            map_report.ParseFromString(payload)

            region_name = None
            if map_report.region:
                try:
                    region_name = config_pb2.Config.LoRaConfig.RegionCode.Name(map_report.region)
                except Exception:
                    pass

            modem_preset_name = None
            if map_report.modem_preset:
                try:
                    modem_preset_name = config_pb2.Config.LoRaConfig.ModemPreset.Name(map_report.modem_preset)
                except Exception:
                    pass

            # Update node database with MAP_REPORT data if available
            if self.node_db and from_node_hex:
                self.node_db.add_node(
                    node_id=from_node_hex,
                    long_name=map_report.long_name if map_report.long_name else None,
                    short_name=map_report.short_name if map_report.short_name else None
                )

            return MapReport(
                long_name=map_report.long_name,
                short_name=map_report.short_name,
                latitude=map_report.latitude_i / 1e7,
                longitude=map_report.longitude_i / 1e7,
                altitude=map_report.altitude,
                firmware_version=map_report.firmware_version,
                region=region_name,
                modem_preset=modem_preset_name
            )
        except Exception:
            return None

    def create_parsed_message(
        self,
        msg,
        service_envelope,
        packet,
        data: Optional[mesh_pb2.Data] = None
    ) -> ParsedMessage:
        """
        Create a complete ParsedMessage from MQTT message components.
        """
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        packet_info = self.parse_packet_info(packet)

        # Track all nodes we see (from and to)
        if self.node_db is not None:
            # Add sender node (always track)
            self.node_db.add_node(packet_info.from_node_hex)

            # Add receiver node if not broadcast
            if packet_info.to_node != 0xffffffff:
                self.node_db.add_node(packet_info.to_node_hex)

        encrypted_payload_b64 = None
        if packet.HasField('encrypted'):
            encrypted_payload_b64 = base64.b64encode(bytes(packet.encrypted)).decode('utf-8')

        decoded_payload_b64 = None
        if packet.HasField('decoded'):
            decoded_payload_b64 = base64.b64encode(packet.decoded.payload).decode('utf-8')

        portnum = 0
        portnum_name = "UNKNOWN"
        content = None

        if data:
            portnum = data.portnum
            try:
                portnum_name = portnums_pb2.PortNum.Name(portnum)
            except ValueError:
                portnum_name = f"UNKNOWN_{portnum}"
            content = self.parse_message_content(portnum, data.payload, packet_info.from_node_hex, packet_info.to_node_hex)

        return ParsedMessage(
            timestamp=timestamp,
            topic=msg.topic,
            channel_id=service_envelope.channel_id,
            gateway_id=service_envelope.gateway_id,
            packet_info=packet_info,
            portnum=portnum,
            portnum_name=portnum_name,
            encrypted=packet.HasField('encrypted'),
            content=content,
            encrypted_payload_b64=encrypted_payload_b64,
            decoded_payload_b64=decoded_payload_b64
        )
