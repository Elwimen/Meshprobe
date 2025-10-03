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


class MessagePublisher:
    """Publishes messages to Meshtastic MQTT broker."""

    def __init__(self, client: mqtt.Client, node_config: NodeConfig, server_config: ServerConfig,
                 channel_keys: dict[str, bytes]):
        """
        Initialize MessagePublisher.

        Args:
            client: MQTT client instance
            node_config: Node configuration
            server_config: Server configuration
            channel_keys: Dictionary of channel PSKs
        """
        self.client = client
        self.node_config = node_config
        self.server_config = server_config
        self.channel_keys = channel_keys

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

        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_text_message(self, text: str, to_node_id: str, channel: int = 0, hop_limit: int = 3) -> bool:
        """Send a text message to a specific node."""
        to_node_num = parse_node_id(to_node_id)
        channel_name = self.node_config.get_channel_name(channel)
        channel_hash = self._get_channel_hash(channel)

        mesh_packet = self._create_text_mesh_packet(text, to_node_num, channel_hash, hop_limit)
        service_envelope = self._create_service_envelope(mesh_packet, channel_name)

        return self._publish_message(service_envelope, to_node_num, "text message", {"Message": text, "Channel": channel_name})

    def send_position_message(self, to_node_id: str, channel: int = 0, hop_limit: int = 3) -> bool:
        """Send position to a specific node."""
        to_node_num = parse_node_id(to_node_id)

        position = self._create_position()
        mesh_packet = self._create_position_mesh_packet(position, to_node_num, 0, hop_limit)
        service_envelope = self._create_service_envelope(mesh_packet)

        details = {"Position": f"{self.node_config.position.latitude}, {self.node_config.position.longitude}"}
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

    def _create_text_mesh_packet(self, text: str, to_node: int, channel_hash: int, hop_limit: int) -> mesh_pb2.MeshPacket:
        """Create MeshPacket with text message."""
        return self._create_base_mesh_packet(
            to_node=to_node,
            portnum=portnums_pb2.TEXT_MESSAGE_APP,
            payload=text.encode('utf-8'),
            channel_hash=channel_hash,
            hop_limit=hop_limit,
            want_ack=False
        )

    def _create_position(self) -> mesh_pb2.Position:
        """Create Position protobuf from config."""
        position = mesh_pb2.Position()
        position.latitude_i = int(self.node_config.position.latitude * 1e7)
        position.longitude_i = int(self.node_config.position.longitude * 1e7)
        position.altitude = self.node_config.position.altitude
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
        result = self.client.publish(self._get_message_topic(), payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_environment(self) -> bool:
        """Send TELEMETRY packet with environment metrics."""
        telemetry = telemetry_pb2.Telemetry()
        telemetry.time = int(time.time())

        env = self.node_config.environment_metrics
        metrics = []

        if env.temperature != 0.0:
            telemetry.environment_metrics.temperature = float(env.temperature)
            metrics.append(f"Temp {env.temperature}°C")
        if env.relative_humidity != 0.0:
            telemetry.environment_metrics.relative_humidity = float(env.relative_humidity)
            metrics.append(f"Humidity {env.relative_humidity}%")
        if env.barometric_pressure != 0.0:
            telemetry.environment_metrics.barometric_pressure = float(env.barometric_pressure)
            metrics.append(f"Pressure {env.barometric_pressure}hPa")
        if env.gas_resistance != 0.0:
            telemetry.environment_metrics.gas_resistance = float(env.gas_resistance)
            metrics.append(f"Gas {env.gas_resistance}Ω")
        if env.voltage != 0.0:
            telemetry.environment_metrics.voltage = float(env.voltage)
            metrics.append(f"Volt {env.voltage}V")
        if env.current != 0.0:
            telemetry.environment_metrics.current = float(env.current)
            metrics.append(f"Current {env.current}mA")
        if env.iaq != 0:
            telemetry.environment_metrics.iaq = int(env.iaq)
            metrics.append(f"IAQ {env.iaq}")
        if env.distance != 0.0:
            telemetry.environment_metrics.distance = float(env.distance)
            metrics.append(f"Distance {env.distance}m")
        if env.lux != 0.0:
            telemetry.environment_metrics.lux = float(env.lux)
            metrics.append(f"Lux {env.lux}")
        if env.white_lux != 0.0:
            telemetry.environment_metrics.white_lux = float(env.white_lux)
            metrics.append(f"WhiteLux {env.white_lux}")
        if env.ir_lux != 0.0:
            telemetry.environment_metrics.ir_lux = float(env.ir_lux)
            metrics.append(f"IR {env.ir_lux}")
        if env.uv_lux != 0.0:
            telemetry.environment_metrics.uv_lux = float(env.uv_lux)
            metrics.append(f"UV {env.uv_lux}")
        if env.wind_direction != 0:
            telemetry.environment_metrics.wind_direction = int(env.wind_direction)
            metrics.append(f"WindDir {env.wind_direction}°")
        if env.wind_speed != 0.0:
            telemetry.environment_metrics.wind_speed = float(env.wind_speed)
            metrics.append(f"WindSpeed {env.wind_speed}m/s")
        if env.weight != 0.0:
            telemetry.environment_metrics.weight = float(env.weight)
            metrics.append(f"Weight {env.weight}kg")
        if env.wind_gust != 0.0:
            telemetry.environment_metrics.wind_gust = float(env.wind_gust)
            metrics.append(f"Gust {env.wind_gust}m/s")
        if env.wind_lull != 0.0:
            telemetry.environment_metrics.wind_lull = float(env.wind_lull)
            metrics.append(f"Lull {env.wind_lull}m/s")
        if env.radiation != 0.0:
            telemetry.environment_metrics.radiation = float(env.radiation)
            metrics.append(f"Radiation {env.radiation}cpm")
        if env.rainfall_1h != 0.0:
            telemetry.environment_metrics.rainfall_1h = float(env.rainfall_1h)
            metrics.append(f"Rain1h {env.rainfall_1h}mm")
        if env.rainfall_24h != 0.0:
            telemetry.environment_metrics.rainfall_24h = float(env.rainfall_24h)
            metrics.append(f"Rain24h {env.rainfall_24h}mm")
        if env.soil_moisture != 0.0:
            telemetry.environment_metrics.soil_moisture = int(env.soil_moisture)
            metrics.append(f"SoilMoisture {env.soil_moisture}%")
        if env.soil_temperature != 0.0:
            telemetry.environment_metrics.soil_temperature = float(env.soil_temperature)
            metrics.append(f"SoilTemp {env.soil_temperature}°C")

        mesh_packet = self._create_base_mesh_packet(
            to_node=0xFFFFFFFF,
            portnum=portnums_pb2.TELEMETRY_APP,
            payload=telemetry.SerializeToString(),
            hop_limit=3
        )
        service_envelope = self._create_service_envelope(mesh_packet)

        print(f"Sending ENVIRONMENT: {', '.join(metrics) if metrics else 'No metrics set'}")

        payload = service_envelope.SerializeToString()
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
