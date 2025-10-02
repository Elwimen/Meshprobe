"""
Main MQTT client for Meshtastic mesh networks.
"""

import time
from typing import Optional

try:
    import paho.mqtt.client as mqtt
    from meshtastic import mqtt_pb2, portnums_pb2
except ImportError as e:
    print(f"Error: Missing required package: {e}")
    import sys
    sys.exit(1)

from .config import ServerConfig, NodeConfig
from .crypto import CryptoEngine
from .parsers import MessageParser
from .formatters import MessageFormatter
from .logger import MessageLogger
from .publishers import MessagePublisher
from .models import Statistics


class MeshtasticMQTTClient:
    """
    Meshtastic MQTT client.
    Orchestrates all components: crypto, parsing, formatting, logging, publishing.
    """

    def __init__(self, server_config: ServerConfig, node_config: NodeConfig,
                 log_file: str = "mqtt_messages.json", openssl_password: Optional[str] = None):
        """
        Initialize MeshtasticMQTTClient.

        Args:
            server_config: Server configuration
            node_config: Node configuration
            log_file: Path to message log file
            openssl_password: Optional password for OpenSSL-encrypted messages
        """
        self.server_config = server_config
        self.node_config = node_config
        self.client: Optional[mqtt.Client] = None
        self.connected = False
        self.subscribe_mode = False

        channel_keys = CryptoEngine.load_channel_keys(node_config.channels)
        self.crypto = CryptoEngine(channel_keys, openssl_password)
        self.parser = MessageParser()
        self.formatter = MessageFormatter(self.crypto)
        self.logger = MessageLogger(log_file)
        self.stats = Statistics()

        self.publisher: Optional[MessagePublisher] = None

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker."""
        if rc == 0:
            print(f"Connected to MQTT broker at {self.server_config.host}:{self.server_config.port}")
            self.connected = True
        else:
            print(f"Failed to connect, return code {rc}")
            self.connected = False

    def on_disconnect(self, client, userdata, rc):
        """Callback when disconnected from MQTT broker."""
        print(f"Disconnected from MQTT broker (code: {rc})")
        self.connected = False

    def on_publish(self, client, userdata, mid):
        """Callback when message is published."""
        print(f"Message published (mid: {mid})")

    def on_message(self, client, userdata, msg):
        """Callback when message is received."""
        self.stats.total_messages += 1

        if '/json/' in msg.topic:
            return

        if self._try_handle_direct_map_report(msg):
            return

        self._handle_service_envelope(msg)

    def _try_handle_direct_map_report(self, msg) -> bool:
        """Try to handle direct MAP REPORT messages on /map/ topics."""
        topic_parts = msg.topic.split('/')

        if len(topic_parts) < 5 or topic_parts[-2] != 'map':
            return False

        if not topic_parts[-1]:
            return False

        try:
            map_report = mqtt_pb2.MapReport()
            map_report.ParseFromString(msg.payload)

            gateway_id = topic_parts[-1]
            lat = map_report.latitude_i / 1e7
            lon = map_report.longitude_i / 1e7

            print(f"\n{'='*60}")
            print(f"Topic: {msg.topic}")
            print(f"From: {gateway_id} → To: !ffffffff")
            print(f"Gateway: {gateway_id}, Channel: unknown")
            print(f"Packet ID: 0x00000000")
            print(f"{'─'*60}")
            print("🗺️  MAP REPORT")
            print(f"   Long name:  {map_report.long_name}")
            print(f"   Short name: {map_report.short_name}")
            print(f"   Position:   {lat:.6f}, {lon:.6f}, {map_report.altitude}m")
            print(f"   Firmware:   {map_report.firmware_version}")

            if map_report.region:
                from meshtastic import config_pb2
                region_name = config_pb2.Config.LoRaConfig.RegionCode.Name(map_report.region)
                print(f"   Region:     {region_name}")

            if map_report.modem_preset:
                from meshtastic import config_pb2
                preset_name = config_pb2.Config.LoRaConfig.ModemPreset.Name(map_report.modem_preset)
                print(f"   Modem:      {preset_name}")

            print(f"{'='*60}")
            return True
        except Exception:
            return False

    def _handle_service_envelope(self, msg):
        """Handle ServiceEnvelope MQTT messages."""
        try:
            service_envelope = mqtt_pb2.ServiceEnvelope()
            service_envelope.ParseFromString(msg.payload)
        except Exception:
            print(f"Error parsing ServiceEnvelope on topic: {msg.topic}")
            print(f"Payload length: {len(msg.payload)} bytes")
            return

        packet = service_envelope.packet
        channel_id = service_envelope.channel_id

        data = None
        if packet.HasField('decoded'):
            data = packet.decoded
        elif packet.HasField('encrypted'):
            data = self.crypto.decrypt_packet(packet, channel_id, debug=False)
            if data:
                self.stats.successful_decrypts += 1
            else:
                self.stats.failed_decrypts += 1
                packet_info = self.parser.parse_packet_info(packet)
                print(f"\n{self.formatter.format_encrypted_failure(packet_info)}\n")
                return

        parsed_msg = self.parser.create_parsed_message(msg, service_envelope, packet, data)

        self.logger.log_message(parsed_msg)

        if data:
            portnum_name = portnums_pb2.PortNum.Name(data.portnum)
            self.stats.increment_portnum(portnum_name)

        print(f"\n{self.formatter.format_message(parsed_msg)}\n")

    def connect(self, use_listener_id: bool = False, subscribe: bool = True) -> bool:
        """
        Connect to MQTT broker.

        Args:
            use_listener_id: Use hashed listener client ID instead of node ID
            subscribe: Whether to subscribe to messages (False for publish-only)

        Returns:
            True if connected successfully, False otherwise
        """
        if use_listener_id:
            import hashlib
            hashed_id = hashlib.sha256(f"{self.node_config.node_id}-listener".encode()).hexdigest()[:8]
            client_id = f"!{hashed_id}"
        else:
            client_id = self.node_config.node_id

        self.client = mqtt.Client(client_id=client_id)
        self.client.username_pw_set(self.server_config.username, self.server_config.password)

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_publish = self.on_publish

        if subscribe:
            self.client.on_message = self.on_message

        try:
            print(f"Connecting to {self.server_config.host}:{self.server_config.port}...")
            if use_listener_id:
                print(f"Using listener client ID: {client_id}")

            self.client.connect(self.server_config.host, self.server_config.port, 60)

            if subscribe:
                self.client.loop_start()

            timeout = 10
            start = time.time()
            while not self.connected and (time.time() - start) < timeout:
                if not subscribe:
                    self.client.loop(timeout=0.1)
                time.sleep(0.1)

            if not self.connected:
                print("Connection timeout")
                return False

            if subscribe:
                subscribe_topic = f"{self.server_config.root_topic}/#"
                print(f"Subscribing to: {subscribe_topic}")
                self.client.subscribe(subscribe_topic, qos=1)

            self.subscribe_mode = subscribe
            self.publisher = MessagePublisher(
                self.client,
                self.node_config,
                self.server_config,
                self.crypto.channel_keys
            )

            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect(self):
        """Disconnect from MQTT broker."""
        if self.client:
            try:
                self.client.loop_stop()
            except Exception:
                pass
            self.client.disconnect()

    def print_stats(self):
        """Print statistics summary."""
        print(f"\n{self.formatter.format_statistics(self.stats)}\n")

    def publish_map_position(self) -> bool:
        """Publish position to the mesh map."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.publish_map_position()

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result

    def send_text_message(self, text: str, to_node_id: str, channel: int = 0, hop_limit: int = 3) -> bool:
        """Send a text message to a specific node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_text_message(text, to_node_id, channel, hop_limit)

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result

    def send_position_message(self, to_node_id: str, channel: int = 0, hop_limit: int = 3) -> bool:
        """Send position to a specific node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_position_message(to_node_id, channel, hop_limit)

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result

    def send_node_info(self) -> bool:
        """Broadcast NODEINFO to announce this node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_node_info()

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result

    def send_telemetry(self) -> bool:
        """Broadcast TELEMETRY with device metrics."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_telemetry()

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result

    def send_environment(self) -> bool:
        """Broadcast TELEMETRY with environment metrics."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_environment()

        if not self.subscribe_mode:
            self.client.loop(timeout=0.1)

        return result
