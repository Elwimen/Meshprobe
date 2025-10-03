"""
Console formatters for Meshtastic messages.
"""

from datetime import datetime, timezone
from typing import Optional

try:
    from meshtastic import mesh_pb2
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic")
    import sys
    sys.exit(1)

from .models import (
    ParsedMessage, TextMessage, PositionData, NodeInfo,
    DeviceTelemetry, EnvironmentTelemetry, RoutingInfo,
    NeighborInfo, MapReport, Statistics
)
from .crypto import CryptoEngine
from .node_db import NodeDatabase
from .hex_dump import hex_dump

# Message formatting width
SEPARATOR_WIDTH = 68


class MessageFormatter:
    """Formatter for console output of Meshtastic messages."""

    def __init__(self, crypto_engine: Optional[CryptoEngine] = None, node_db: Optional[NodeDatabase] = None,
                 hex_dump: Optional[str] = None, hex_dump_colored: bool = False):
        """
        Initialize MessageFormatter.

        Args:
            crypto_engine: Optional CryptoEngine for decrypting OpenSSL messages
            node_db: Optional NodeDatabase for displaying node names
            hex_dump: Hex dump mode: 'encrypted', 'decrypted', or 'all' (None = disabled)
            hex_dump_colored: Use colored output in hex dump
        """
        self.crypto_engine = crypto_engine
        self.node_db = node_db
        self.hex_dump = hex_dump
        self.hex_dump_colored = hex_dump_colored

    def format_message(self, parsed_msg: ParsedMessage) -> str:
        """
        Format a parsed message for console output.

        Args:
            parsed_msg: ParsedMessage to format

        Returns:
            Formatted string for console output
        """
        lines = []
        lines.append("=" * SEPARATOR_WIDTH)

        # Add local receive timestamp
        receive_time = datetime.now()
        lines.append(f"Received at: {receive_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

        lines.append(f"Topic: {parsed_msg.topic}")

        # Format From/To with node names if available
        from_display = parsed_msg.packet_info.from_node_hex
        to_display = parsed_msg.packet_info.to_node_hex

        if self.node_db is not None:
            from_name = self.node_db.get_display_name(parsed_msg.packet_info.from_node_hex)
            to_name = self.node_db.get_display_name(parsed_msg.packet_info.to_node_hex)
            from_display += from_name
            to_display += to_name

        lines.append(f"From: {from_display} → To: {to_display}")
        lines.append(f"Gateway: {parsed_msg.gateway_id}, Channel: {parsed_msg.channel_id}")

        if parsed_msg.packet_info.hops_away > 0:
            lines.append(
                f"Hops: {parsed_msg.packet_info.hops_away} away "
                f"(limit={parsed_msg.packet_info.hop_limit}, start={parsed_msg.packet_info.hop_start})"
            )

        if parsed_msg.packet_info.via_mqtt:
            lines.append("Via: MQTT")

        if parsed_msg.packet_info.want_ack:
            lines.append("Want ACK: Yes")

        lines.append(f"Packet ID: {parsed_msg.packet_info.packet_id_hex}")
        lines.append("─" * SEPARATOR_WIDTH)

        if parsed_msg.content:
            lines.append(self._format_content(parsed_msg.content))
        else:
            lines.append("Unable to decode message")

        # Show hex dump for decrypted payloads if enabled
        if self.hex_dump in ('decrypted', 'all') and parsed_msg.decoded_payload_b64:
            import base64
            payload_bytes = base64.b64decode(parsed_msg.decoded_payload_b64)
            lines.append("─" * SEPARATOR_WIDTH)
            lines.append(f"Raw payload ({len(payload_bytes)} bytes):")
            lines.append(hex_dump(payload_bytes, use_color=self.hex_dump_colored))

        lines.append("=" * SEPARATOR_WIDTH)
        return "\n".join(lines)

    def _format_content(self, content) -> str:
        """Format message content based on type."""
        match content:
            case TextMessage():
                return self._format_text_message(content)
            case PositionData():
                return self._format_position(content)
            case NodeInfo():
                return self._format_nodeinfo(content)
            case DeviceTelemetry():
                return self._format_device_telemetry(content)
            case EnvironmentTelemetry():
                return self._format_environment_telemetry(content)
            case RoutingInfo():
                return self._format_routing(content)
            case NeighborInfo():
                return self._format_neighborinfo(content)
            case MapReport():
                return self._format_map_report(content)
            case _:
                return "Unknown message type"

    def _format_text_message(self, msg: TextMessage) -> str:
        """Format text message."""
        lines = ["💬 TEXT MESSAGE"]

        if msg.is_openssl_encrypted and self.crypto_engine:
            decrypted = self.crypto_engine.decrypt_openssl_salted(msg.text)
            if decrypted:
                lines.append(f"   🔓 {decrypted}")
            else:
                lines.append(f"   🔒 {msg.text}")
                if self.crypto_engine.openssl_password:
                    lines.append("   (Failed to decrypt with provided password)")
                else:
                    lines.append("   (Encrypted with OpenSSL - use --openssl-password to decrypt)")
        else:
            lines.append(f"   {msg.text}")

        return "\n".join(lines)

    @staticmethod
    def _format_position(pos: PositionData) -> str:
        """Format position data."""
        lines = ["📍 POSITION"]
        lines.append(f"   Latitude:  {pos.latitude:.6f}°")
        lines.append(f"   Longitude: {pos.longitude:.6f}°")
        lines.append(f"   Altitude:  {pos.altitude}m")

        if pos.time:
            ts = datetime.fromtimestamp(pos.time, tz=timezone.utc)
            lines.append(f"   Time:      {ts.isoformat()}")

        return "\n".join(lines)

    @staticmethod
    def _format_nodeinfo(info: NodeInfo) -> str:
        """Format node info."""
        lines = ["ℹ️  NODE INFO"]

        if info.long_name:
            lines.append(f"   Long name:  {info.long_name}")
        if info.short_name:
            lines.append(f"   Short name: {info.short_name}")
        if info.node_id:
            lines.append(f"   Node ID:    {info.node_id}")
        if info.macaddr:
            lines.append(f"   MAC:        {info.macaddr}")
        if info.hw_model_name:
            lines.append(f"   Hardware:   {info.hw_model_name}")
        elif info.hw_model:
            lines.append(f"   Hardware:   {info.hw_model} (unknown)")

        return "\n".join(lines)

    @staticmethod
    def _format_device_telemetry(telemetry: DeviceTelemetry) -> str:
        """Format device telemetry."""
        lines = ["📊 DEVICE TELEMETRY"]

        if telemetry.battery_level:
            if 0 < telemetry.battery_level <= 100:
                lines.append(f"   Battery:    {telemetry.battery_level:.0f}%")
            elif telemetry.battery_level == 101:
                lines.append("   Battery:    Plugged in")

        if telemetry.voltage and telemetry.voltage > 0:
            lines.append(f"   Voltage:    {telemetry.voltage:.2f}V")

        if telemetry.channel_utilization and telemetry.channel_utilization > 0:
            lines.append(f"   Ch. Util:   {telemetry.channel_utilization:.1f}%")

        if telemetry.air_util_tx and telemetry.air_util_tx > 0:
            lines.append(f"   Air TX:     {telemetry.air_util_tx:.1f}%")

        if telemetry.uptime_seconds and telemetry.uptime_seconds > 0:
            hours = telemetry.uptime_seconds // 3600
            minutes = (telemetry.uptime_seconds % 3600) // 60
            lines.append(f"   Uptime:     {hours}h {minutes}m")

        return "\n".join(lines)

    @staticmethod
    def _format_environment_telemetry(telemetry: EnvironmentTelemetry) -> str:
        """Format environment telemetry."""
        lines = ["🌡️  ENVIRONMENT TELEMETRY"]

        if telemetry.temperature and telemetry.temperature != 0:
            lines.append(f"   Temperature:      {telemetry.temperature:.1f}°C")
        if telemetry.relative_humidity and telemetry.relative_humidity != 0:
            lines.append(f"   Humidity:         {telemetry.relative_humidity:.1f}%")
        if telemetry.barometric_pressure and telemetry.barometric_pressure != 0:
            lines.append(f"   Pressure:         {telemetry.barometric_pressure:.1f} hPa")
        if telemetry.gas_resistance and telemetry.gas_resistance != 0:
            lines.append(f"   Gas Resistance:   {telemetry.gas_resistance:.0f} Ω")
        if telemetry.voltage and telemetry.voltage != 0:
            lines.append(f"   Voltage:          {telemetry.voltage:.2f} V")
        if telemetry.current and telemetry.current != 0:
            lines.append(f"   Current:          {telemetry.current:.1f} mA")
        if telemetry.iaq and telemetry.iaq != 0:
            lines.append(f"   IAQ:              {telemetry.iaq}")
        if telemetry.distance and telemetry.distance != 0:
            lines.append(f"   Distance:         {telemetry.distance:.1f} m")
        if telemetry.lux and telemetry.lux != 0:
            lines.append(f"   Lux:              {telemetry.lux:.1f}")
        if telemetry.white_lux and telemetry.white_lux != 0:
            lines.append(f"   White Lux:        {telemetry.white_lux:.1f}")
        if telemetry.ir_lux and telemetry.ir_lux != 0:
            lines.append(f"   IR Lux:           {telemetry.ir_lux:.1f}")
        if telemetry.uv_lux and telemetry.uv_lux != 0:
            lines.append(f"   UV Lux:           {telemetry.uv_lux:.1f}")
        if telemetry.wind_direction and telemetry.wind_direction != 0:
            lines.append(f"   Wind Direction:   {telemetry.wind_direction}°")
        if telemetry.wind_speed and telemetry.wind_speed != 0:
            lines.append(f"   Wind Speed:       {telemetry.wind_speed:.1f} m/s")
        if telemetry.wind_gust and telemetry.wind_gust != 0:
            lines.append(f"   Wind Gust:        {telemetry.wind_gust:.1f} m/s")
        if telemetry.wind_lull and telemetry.wind_lull != 0:
            lines.append(f"   Wind Lull:        {telemetry.wind_lull:.1f} m/s")
        if telemetry.weight and telemetry.weight != 0:
            lines.append(f"   Weight:           {telemetry.weight:.1f} kg")
        if telemetry.radiation and telemetry.radiation != 0:
            lines.append(f"   Radiation:        {telemetry.radiation:.1f} cpm")
        if telemetry.rainfall_1h and telemetry.rainfall_1h != 0:
            lines.append(f"   Rainfall (1h):    {telemetry.rainfall_1h:.1f} mm")
        if telemetry.rainfall_24h and telemetry.rainfall_24h != 0:
            lines.append(f"   Rainfall (24h):   {telemetry.rainfall_24h:.1f} mm")
        if telemetry.soil_moisture and telemetry.soil_moisture != 0:
            lines.append(f"   Soil Moisture:    {telemetry.soil_moisture:.1f}%")
        if telemetry.soil_temperature and telemetry.soil_temperature != 0:
            lines.append(f"   Soil Temperature: {telemetry.soil_temperature:.1f}°C")

        return "\n".join(lines)

    @staticmethod
    def _format_routing(routing: RoutingInfo) -> str:
        """Format routing info."""
        lines = ["🔄 ROUTING"]
        lines.append(f"   Type: {routing.error_reason}")
        return "\n".join(lines)

    @staticmethod
    def _format_neighborinfo(info: NeighborInfo) -> str:
        """Format neighbor info."""
        lines = ["🔗 NEIGHBOR INFO"]
        lines.append(f"   Reporter:   {info.reporter_node_hex}")

        if info.via_node_hex:
            lines.append(f"   Via:        {info.via_node_hex}")

        if info.broadcast_interval_secs > 0:
            lines.append(f"   Interval:   {info.broadcast_interval_secs}s")

        lines.append(f"   Neighbors:  {len(info.neighbors)}")
        for nbr in info.neighbors:
            lines.append(f"     - {nbr.node_id_hex} SNR: {nbr.snr:.1f}dB")

        return "\n".join(lines)

    @staticmethod
    def _format_map_report(report: MapReport) -> str:
        """Format map report."""
        lines = ["🗺️  MAP REPORT"]
        lines.append(f"   Long name:  {report.long_name}")
        lines.append(f"   Short name: {report.short_name}")
        lines.append(f"   Position:   {report.latitude:.6f}, {report.longitude:.6f}, {report.altitude}m")
        lines.append(f"   Firmware:   {report.firmware_version}")

        if report.region:
            lines.append(f"   Region:     {report.region}")

        if report.modem_preset:
            lines.append(f"   Modem:      {report.modem_preset}")

        return "\n".join(lines)

    @staticmethod
    def format_statistics(stats: Statistics) -> str:
        """Format statistics summary."""
        lines = []
        lines.append("=" * SEPARATOR_WIDTH)
        lines.append("STATISTICS SUMMARY")
        lines.append("=" * SEPARATOR_WIDTH)
        lines.append(f"Total messages:       {stats.total_messages}")
        lines.append(f"Parse errors:         {stats.parse_errors}")
        lines.append(f"Successful decrypts:  {stats.successful_decrypts}")
        lines.append(f"Failed decrypts:      {stats.failed_decrypts}")

        if stats.portnum_counts:
            lines.append("")
            lines.append("Messages by PortNum:")
            for portnum_name, count in stats.get_sorted_portnums():
                lines.append(f"  {portnum_name:25s} {count:5d}")

        lines.append("=" * SEPARATOR_WIDTH)
        return "\n".join(lines)

    def format_encrypted_failure(self, packet_info, encrypted_data: bytes = None) -> str:
        """Format message for failed decryption."""
        lines = []
        lines.append("=" * SEPARATOR_WIDTH)
        lines.append(f"From: {packet_info.from_node_hex} → To: {packet_info.to_node_hex}")
        lines.append(f"Packet ID: {packet_info.packet_id_hex}")
        lines.append("─" * SEPARATOR_WIDTH)

        if self.hex_dump in ('encrypted', 'all') and encrypted_data:
            lines.append(f"🔒 Encrypted payload ({len(encrypted_data)} bytes):")
            lines.append(hex_dump(encrypted_data, use_color=self.hex_dump_colored))
        else:
            lines.append("🔒 ENCRYPTED (unable to decrypt)")

        lines.append("=" * SEPARATOR_WIDTH)
        return "\n".join(lines)
