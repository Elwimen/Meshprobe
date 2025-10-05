"""
Message publishers for Meshtastic MQTT client.
"""

import time
import random

try:
    import paho.mqtt.client as mqtt
    from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, config_pb2, telemetry_pb2
except ImportError as e:
    print(f"Error: Missing required package: {e}")
    import sys
    sys.exit(1)

from .config import NodeConfig, ServerConfig
from .crypto import CryptoEngine
from .utils import parse_node_id
from .hex_dump import hex_dump
from .formatters import SEPARATOR_WIDTH

# Environment field configuration for send_environment
# Format: (field_name, protobuf_type, unit, display_name)
ENV_FIELD_CONFIG = [
    ('temperature', float, '°C', 'Temp'),
    ('relative_humidity', float, '%', 'Humidity'),
    ('barometric_pressure', float, 'hPa', 'Pressure'),
    ('gas_resistance', float, 'Ω', 'Gas'),
    ('voltage', float, 'V', 'Volt'),
    ('current', float, 'mA', 'Current'),
    ('iaq', int, '', 'IAQ'),
    ('distance', float, 'm', 'Distance'),
    ('lux', float, '', 'Lux'),
    ('white_lux', float, '', 'WhiteLux'),
    ('ir_lux', float, '', 'IR'),
    ('uv_lux', float, '', 'UV'),
    ('wind_direction', int, '°', 'WindDir'),
    ('wind_speed', float, 'm/s', 'WindSpeed'),
    ('weight', float, 'kg', 'Weight'),
    ('wind_gust', float, 'm/s', 'Gust'),
    ('wind_lull', float, 'm/s', 'Lull'),
    ('radiation', float, 'cpm', 'Radiation'),
    ('rainfall_1h', float, 'mm', 'Rain1h'),
    ('rainfall_24h', float, 'mm', 'Rain24h'),
    ('soil_moisture', int, '%', 'SoilMoisture'),
    ('soil_temperature', float, '°C', 'SoilTemp'),
]


class MessagePublisher:
    """Publishes messages to Meshtastic MQTT broker."""

    def __init__(self, client: mqtt.Client, node_config: NodeConfig, server_config: ServerConfig,
                 channel_keys: dict[str, bytes], hex_dump_mode=None, hex_dump_colored: bool = False,
                 openssl_password: str | None = None, openssl_send_base64: bool = False,
                 openssl_iterations: int = 10000, openssl_fixed_salt: bytes | None = None):
        """
        Initialize MessagePublisher.

        Args:
            client: MQTT client instance
            node_config: Node configuration
            server_config: Server configuration
            channel_keys: Dictionary of channel PSKs
            hex_dump_mode: Enable hex dump for transmitted packets (True or string mode)
            hex_dump_colored: Use colored output in hex dump
        """
        self.client = client
        self.node_config = node_config
        self.server_config = server_config
        self.channel_keys = channel_keys
        self.hex_dump_mode = hex_dump_mode
        self.hex_dump_colored = hex_dump_colored
        self.openssl_password = openssl_password
        self.openssl_send_base64 = openssl_send_base64
        self.openssl_iterations = int(openssl_iterations) if openssl_iterations else 10000
        self.openssl_fixed_salt = openssl_fixed_salt

    def _print_hex_dump(self, payload: bytes, label: str = "Packet"):
        """Print hex dump of payload if enabled."""
        if not self.hex_dump_mode:
            return

        print(f"\n{'─' * SEPARATOR_WIDTH}")
        print(f"{label} hex dump ({len(payload)} bytes):")
        print(f"{'─' * SEPARATOR_WIDTH}")
        dump = hex_dump(payload, use_color=self.hex_dump_colored)
        print(dump)
        print(f"{'─' * SEPARATOR_WIDTH}\n")

    def publish_map_position(self) -> bool:
        """Publish position to the mesh map using protobuf MapReport."""
        root = self.server_config.root_topic
        topic = f"{root}/2/map"

        base_lat = self.node_config.position.latitude
        base_lon = self.node_config.position.longitude
        base_alt = self.node_config.position.altitude

        lat = random.gauss(base_lat, 0.025 / 3)
        lon = random.gauss(base_lon, 0.025 / 3)
        alt = random.gauss(base_alt, 50 / 3)

        lat_i = int(lat * 1e7)
        lon_i = int(lon * 1e7)

        region = self._get_region_enum()
        modem_preset = self._get_modem_preset_enum()

        map_report = self._create_map_report(lat_i, lon_i, int(alt), region, modem_preset)
        mesh_packet = self._create_mesh_packet_for_map(map_report)
        service_envelope = self._create_service_envelope(mesh_packet)

        payload = service_envelope.SerializeToString()

        self._print_map_publish_info(base_lat, base_lon, base_alt, lat, lon, alt, region, modem_preset, len(payload))
        self._print_hex_dump(payload, "MAP_REPORT ServiceEnvelope")

        result = self.client.publish(topic, payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def _get_channel_hash(self, channel: int) -> int:
        """Get channel hash, using PSK if channel is 0."""
        if channel != 0:
            return channel
        psk = self.channel_keys.get(self.node_config.channel) or self.channel_keys.get('default')
        return CryptoEngine.calculate_channel_hash(psk)

    def _get_message_topic(self) -> str:
        """Get topic for sending messages."""
        return f"{self.server_config.root_topic}/2/e/{self.node_config.channel}/{self.node_config.node_id}"

    def _publish_message(self, service_envelope: mqtt_pb2.ServiceEnvelope, to_node_num: int, msg_type: str, details: dict) -> bool:
        """Publish a message and print info."""
        payload = service_envelope.SerializeToString()

        print(f"Sending {msg_type} to node !{to_node_num:08x} (decimal: {to_node_num})")
        print(f"Topic: {self._get_message_topic()}")
        for key, value in details.items():
            print(f"{key}: {value}")
        print(f"Payload size: {len(payload)} bytes")

        self._print_hex_dump(payload, f"{msg_type.upper()} ServiceEnvelope")

        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_text_message(self, text: str, to_node_id: str, channel: int = 0, hop_limit: int = 3) -> bool:
        """Send a text message to a specific node."""
        to_node_num = parse_node_id(to_node_id)
        channel_name = self.node_config.get_channel_name(channel)
        channel_hash = self._get_channel_hash(channel)

        # Encrypt with OpenSSL salted format if password provided
        if self.openssl_password:
            try:
                ce = CryptoEngine({}, self.openssl_password, self.openssl_iterations)
                if self.openssl_send_base64:
                    b64 = ce.encrypt_openssl_salted(text, output="base64", salt=self.openssl_fixed_salt)
                    payload = b64.encode('utf-8')
                else:
                    payload = ce.encrypt_openssl_salted(text, output="bytes", salt=self.openssl_fixed_salt)
                    # Debug: also show Base64 of raw Salted__ for easy comparison on receive
                    try:
                        import base64
                        b64 = base64.b64encode(payload).decode('ascii')
                        print(f"Salted payload (base64): {b64}")
                    except Exception:
                        pass
            except Exception as e:
                print(f"Failed to OpenSSL-encrypt message: {e}")
                return False
        else:
            payload = text.encode('utf-8')

        mesh_packet = self._create_text_mesh_packet(payload, to_node_num, channel_hash, hop_limit)
        service_envelope = self._create_service_envelope(mesh_packet, channel_name)

        return self._publish_message(service_envelope, to_node_num, "text message", {"Message": text, "Channel": channel_name})

    def send_position_message(self, to_node_id: str, channel: int = 0, hop_limit: int = 3, randomize: bool = False) -> bool:
        """Send position to a specific node."""
        to_node_num = parse_node_id(to_node_id)

        if randomize:
            base_lat = self.node_config.position.latitude
            base_lon = self.node_config.position.longitude
            base_alt = self.node_config.position.altitude

            # Use same randomization as map command
            lat = random.gauss(base_lat, 0.025 / 3)
            lon = random.gauss(base_lon, 0.025 / 3)
            alt = random.gauss(base_alt, 50 / 3)

            position = self._create_position_with_coords(lat, lon, int(alt))
            details = {
                "Position": f"{lat:.6f}, {lon:.6f}, {int(alt)}m",
                "Base": f"{base_lat:.6f}, {base_lon:.6f}, {base_alt}m (randomized)"
            }
        else:
            position = self._create_position()
            details = {"Position": f"{self.node_config.position.latitude}, {self.node_config.position.longitude}"}

        mesh_packet = self._create_position_mesh_packet(position, to_node_num, 0, hop_limit)
        service_envelope = self._create_service_envelope(mesh_packet)

        return self._publish_message(service_envelope, to_node_num, "position", details)

    def _randomize_position(self) -> tuple[float, float, float]:
        """Randomize position within ±0.0025 degrees."""
        base_lat = self.node_config.position.latitude
        base_lon = self.node_config.position.longitude
        base_alt = self.node_config.position.altitude

        randomized_lat = random.gauss(base_lat, 0.0025 / 3)
        randomized_lon = random.gauss(base_lon, 0.0025 / 3)
        randomized_alt = random.gauss(base_alt + 100, 100 / 3)

        randomized_lat = max(base_lat - 0.0025, min(base_lat + 0.0025, randomized_lat))
        randomized_lon = max(base_lon - 0.0025, min(base_lon + 0.0025, randomized_lon))
        randomized_alt = max(base_alt, min(base_alt + 200, randomized_alt))

        return randomized_lat, randomized_lon, randomized_alt

    def _apply_position_precision(self, lat_i: int, lon_i: int) -> tuple[int, int]:
        """Apply position precision to coordinates."""
        precision = self.node_config.position.precision
        lat_i = (lat_i & (0xFFFFFFFF << (32 - precision))) + (1 << (31 - precision))
        lon_i = (lon_i & (0xFFFFFFFF << (32 - precision))) + (1 << (31 - precision))
        return lat_i, lon_i

    def _get_region_enum(self) -> int:
        """Get region enum value from config."""
        return getattr(config_pb2.Config.LoRaConfig, self.node_config.region,
                      config_pb2.Config.LoRaConfig.UNSET)

    def _get_modem_preset_enum(self) -> int:
        """Get modem preset enum value from config."""
        return getattr(config_pb2.Config.LoRaConfig, self.node_config.modem_preset,
                      config_pb2.Config.LoRaConfig.LONG_FAST)

    def _create_map_report(self, lat_i: int, lon_i: int, alt: int, region: int, modem_preset: int) -> mqtt_pb2.MapReport:
        """Create MapReport protobuf."""
        map_report = mqtt_pb2.MapReport()
        map_report.long_name = self.node_config.long_name
        map_report.short_name = self.node_config.short_name
        map_report.role = self.node_config.role
        map_report.hw_model = self.node_config.hw_model
        map_report.firmware_version = self.node_config.firmware_version
        map_report.region = region
        map_report.modem_preset = modem_preset
        map_report.has_default_channel = self.node_config.has_default_channel
        map_report.latitude_i = lat_i
        map_report.longitude_i = lon_i
        map_report.altitude = alt
        map_report.position_precision = 32
        map_report.num_online_local_nodes = 1
        map_report.has_opted_report_location = True
        return map_report

    def _create_base_mesh_packet(self, to_node: int, portnum: int, payload: bytes,
                                 channel_hash: int = 0, hop_limit: int = 3,
                                 want_ack: bool = False, add_rx_time: bool = False) -> mesh_pb2.MeshPacket:
        """Create base MeshPacket with common fields."""
        mesh_packet = mesh_pb2.MeshPacket()
        setattr(mesh_packet, 'from', self.node_config.node_num)
        mesh_packet.to = to_node
        mesh_packet.id = int(time.time()) & 0xFFFFFFFF
        mesh_packet.hop_limit = hop_limit
        mesh_packet.hop_start = hop_limit

        if channel_hash:
            mesh_packet.channel = channel_hash
        if add_rx_time:
            mesh_packet.rx_time = int(time.time())

        mesh_packet.want_ack = want_ack
        mesh_packet.decoded.portnum = portnum
        mesh_packet.decoded.payload = payload
        return mesh_packet

    def _create_mesh_packet_for_map(self, map_report: mqtt_pb2.MapReport) -> mesh_pb2.MeshPacket:
        """Create MeshPacket with MapReport."""
        return self._create_base_mesh_packet(
            to_node=0xFFFFFFFF,
            portnum=portnums_pb2.MAP_REPORT_APP,
            payload=map_report.SerializeToString(),
            add_rx_time=True
        )

    def _create_text_mesh_packet(self, payload: bytes, to_node: int, channel_hash: int, hop_limit: int) -> mesh_pb2.MeshPacket:
        """Create MeshPacket with text message from bytes payload."""
        return self._create_base_mesh_packet(
            to_node=to_node,
            portnum=portnums_pb2.TEXT_MESSAGE_APP,
            payload=payload,
            channel_hash=channel_hash,
            hop_limit=hop_limit,
            want_ack=False
        )

    def _create_position(self) -> mesh_pb2.Position:
        """Create Position protobuf from config."""
        return self._create_position_with_coords(
            self.node_config.position.latitude,
            self.node_config.position.longitude,
            self.node_config.position.altitude
        )

    def _create_position_with_coords(self, lat: float, lon: float, alt: int) -> mesh_pb2.Position:
        """Create Position protobuf with specific coordinates."""
        position = mesh_pb2.Position()
        position.latitude_i = int(lat * 1e7)
        position.longitude_i = int(lon * 1e7)
        position.altitude = alt
        position.time = int(time.time())
        return position

    def _create_position_mesh_packet(self, position: mesh_pb2.Position, to_node: int,
                                    channel_hash: int, hop_limit: int) -> mesh_pb2.MeshPacket:
        """Create MeshPacket with position."""
        return self._create_base_mesh_packet(
            to_node=to_node,
            portnum=portnums_pb2.POSITION_APP,
            payload=position.SerializeToString(),
            channel_hash=channel_hash,
            hop_limit=hop_limit,
            want_ack=False,
            add_rx_time=True
        )

    def _create_service_envelope(self, mesh_packet: mesh_pb2.MeshPacket, channel_name: str = None) -> mqtt_pb2.ServiceEnvelope:
        """Create ServiceEnvelope wrapping MeshPacket."""
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)
        service_envelope.channel_id = channel_name or self.node_config.channel
        service_envelope.gateway_id = self.node_config.node_id
        return service_envelope

    def send_node_info(self) -> bool:
        """Send NODEINFO packet to broadcast our node information."""
        user = mesh_pb2.User()
        user.id = self.node_config.node_id
        user.long_name = self.node_config.long_name
        user.short_name = self.node_config.short_name
        user.hw_model = self.node_config.hw_model

        mesh_packet = self._create_base_mesh_packet(
            to_node=0xFFFFFFFF,
            portnum=portnums_pb2.NODEINFO_APP,
            payload=user.SerializeToString(),
            hop_limit=3
        )
        service_envelope = self._create_service_envelope(mesh_packet)

        print(f"Sending NODEINFO for {self.node_config.long_name} ({self.node_config.node_id})")
        print(f"Hardware: {self.node_config.hw_model}, Short name: {self.node_config.short_name}")

        payload = service_envelope.SerializeToString()
        self._print_hex_dump(payload, "NODEINFO ServiceEnvelope")

        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_telemetry(self) -> bool:
        """Send TELEMETRY packet with device metrics."""
        telemetry = telemetry_pb2.Telemetry()
        telemetry.time = int(time.time())
        telemetry.device_metrics.battery_level = int(self.node_config.device_metrics.battery_level)
        telemetry.device_metrics.voltage = float(self.node_config.device_metrics.voltage)
        telemetry.device_metrics.channel_utilization = float(self.node_config.device_metrics.channel_utilization)
        telemetry.device_metrics.air_util_tx = float(self.node_config.device_metrics.air_util_tx)
        if self.node_config.device_metrics.uptime_seconds:
            telemetry.device_metrics.uptime_seconds = int(self.node_config.device_metrics.uptime_seconds)

        mesh_packet = self._create_base_mesh_packet(
            to_node=0xFFFFFFFF,
            portnum=portnums_pb2.TELEMETRY_APP,
            payload=telemetry.SerializeToString(),
            hop_limit=3
        )
        service_envelope = self._create_service_envelope(mesh_packet)

        print(f"Sending TELEMETRY: Battery {self.node_config.device_metrics.battery_level}%, "
              f"Voltage {self.node_config.device_metrics.voltage}V")

        payload = service_envelope.SerializeToString()
        self._print_hex_dump(payload, "TELEMETRY ServiceEnvelope")

        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_environment(self) -> bool:
        """Send TELEMETRY packet with environment metrics."""
        telemetry = telemetry_pb2.Telemetry()
        telemetry.time = int(time.time())

        env = self.node_config.environment_metrics
        metrics = []

        for field_name, field_type, unit, display_name in ENV_FIELD_CONFIG:
            value = getattr(env, field_name, None)

            # Skip zero or None values
            if value is None or value == 0 or (isinstance(value, float) and value == 0.0):
                continue

            # Set protobuf field
            setattr(telemetry.environment_metrics, field_name, field_type(value))

            # Format display message
            metrics.append(f"{display_name} {value}{unit}")

        mesh_packet = self._create_base_mesh_packet(
            to_node=0xFFFFFFFF,
            portnum=portnums_pb2.TELEMETRY_APP,
            payload=telemetry.SerializeToString(),
            hop_limit=3
        )
        service_envelope = self._create_service_envelope(mesh_packet)

        print(f"Sending ENVIRONMENT: {', '.join(metrics) if metrics else 'No metrics set'}")

        payload = service_envelope.SerializeToString()
        self._print_hex_dump(payload, "ENVIRONMENT ServiceEnvelope")

        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def _print_map_publish_info(self, base_lat: float, base_lon: float, base_alt: float,
                                lat: float, lon: float, alt: float, region: int, modem_preset: int, payload_size: int):
        """Print information about map position publish."""
        root = self.server_config.root_topic
        topic = f"{root}/2/map"

        print(f"Publishing map report to topic: {topic}")
        print(f"Node: {self.node_config.long_name} ({self.node_config.node_id})")
        print(f"Short name: {self.node_config.short_name}")
        print(f"Base position: {base_lat:.6f}, {base_lon:.6f}, {base_alt:.1f}m")
        print(f"Published position: {lat:.6f}, {lon:.6f}, {alt:.1f}m")
        print(f"Region: {self.node_config.region}, Modem: {self.node_config.modem_preset}")
        print(f"Firmware: {self.node_config.firmware_version}")
        print(f"Hardware: {self.node_config.hw_model}")
        print(f"Role: {self.node_config.role}")
        print(f"Channel: {self.node_config.channel}, Default channel: {self.node_config.has_default_channel}")
        print(f"Payload size: {payload_size} bytes")
