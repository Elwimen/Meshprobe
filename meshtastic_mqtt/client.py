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

from .config import ServerConfig, NodeConfig, ClientConfig
from .crypto import CryptoEngine
from .parsers import MessageParser
from .formatters import MessageFormatter, SEPARATOR_WIDTH
from .publishers import MessagePublisher
from .models import Statistics
from .node_db import NodeDatabase
from .logging_config import get_logger
from .message_filter import MessageFilter
from .utils import is_json_payload, is_ascii_text

logger = get_logger('client')


class MeshtasticMQTTClient:
    """
    Meshtastic MQTT client.
    Orchestrates all components: crypto, parsing, formatting, logging, publishing.
    """

    def __init__(self, server_config: ServerConfig, node_config: NodeConfig,
                 client_config: ClientConfig, openssl_password: Optional[str] = None,
                 hex_dump: Optional[str] = None, hex_dump_colored: bool = False,
                 filter_types: Optional[dict] = None):
        """
        Initialize MeshtasticMQTTClient.

        Args:
            server_config: Server configuration
            node_config: Node configuration
            client_config: Client configuration
            openssl_password: Optional password for OpenSSL-encrypted messages
            hex_dump: Hex dump mode: 'full', 'payload', 'encrypted', 'decrypted', or True (None = disabled)
            hex_dump_colored: Use colored output in hex dump
            filter_types: Dict with 'include' and 'exclude' sets (None = show all)
        """
        self.server_config = server_config
        self.node_config = node_config
        self.client_config = client_config
        self.client: Optional[mqtt.Client] = None
        self.connected = False
        self.subscribe_mode = False

        self.node_db = NodeDatabase(
            nodes_dir=client_config.nodes_dir,
            flush_interval=client_config.node_db_flush_interval
        )
        channel_keys = CryptoEngine.load_channel_keys(node_config.channels)
        openssl_iters = getattr(client_config, 'openssl_pbkdf2_iter', 10000)
        self.crypto = CryptoEngine(channel_keys, openssl_password, openssl_iterations=openssl_iters)
        self.parser = MessageParser(self.node_db)
        self.formatter = MessageFormatter(self.crypto, self.node_db, hex_dump, hex_dump_colored)
        self.stats = Statistics()
        self.message_filter = MessageFilter(filter_types)

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
        logger.debug(f"Received message: topic={msg.topic}, payload_len={len(msg.payload)}")

        if is_json_payload(msg.payload):
            logger.debug("Skipping JSON payload")
            return

        # Prepare raw MQTT dump if requested
        raw_dump_text = None
        try:
            if getattr(self.formatter, 'hex_dump', None) == 'raw':
                from .hex_dump import hex_dump
                lines = []
                lines.append("=" * SEPARATOR_WIDTH)
                lines.append(f"RAW MQTT MESSAGE ({len(msg.payload)} bytes)")
                lines.append(f"Topic: {msg.topic}")
                lines.append("─" * SEPARATOR_WIDTH)
                lines.append(hex_dump(msg.payload, use_color=self.formatter.hex_dump_colored))
                lines.append("=" * SEPARATOR_WIDTH)
                raw_dump_text = "\n".join(lines)
        except Exception:
            raw_dump_text = None

        if is_ascii_text(msg.payload):
            text = msg.payload.decode('ascii').strip()
            logger.debug(f"ASCII text message on {msg.topic}: {text}")

            # Check if ASCII messages are filtered
            if self.message_filter.should_filter_ascii():
                logger.debug("Filtered out ASCII message")
                return

            # Apply refined SALTED filter for ASCII payloads
            try:
                is_salted_ascii = self.message_filter.is_salted_ascii(msg.payload, text)
                if self.message_filter.should_filter_salted(is_salted_ascii):
                    logger.debug("Filtered out SALTED ASCII message (refined filter)")
                    return
            except Exception:
                pass

            # Display ASCII message; if raw present, print it and avoid extra top separator
            if raw_dump_text:
                print(f"\n{raw_dump_text}")
            print(f"\n{'=' * SEPARATOR_WIDTH}")
            print(f"ASCII: {msg.topic}")
            print(f"{'─' * SEPARATOR_WIDTH}")
            print(f"{text}")
            print(f"{'=' * SEPARATOR_WIDTH}\n")
            return

        if self._try_handle_direct_map_report(msg):
            logger.debug("Handled as direct map report")
            if raw_dump_text:
                # Print raw first, then the map report which already includes separators
                print(f"\n{raw_dump_text}")
            return

        self._handle_service_envelope(msg, raw_dump_text)

    def _get_portnum_name(self, portnum: int) -> str:
        """
        Get portnum name with fallback for unknown values.

        Args:
            portnum: Portnum integer value

        Returns:
            Portnum name or UNKNOWN_PORTNUM_{value} for unknown portnums
        """
        try:
            return portnums_pb2.PortNum.Name(portnum)
        except ValueError:
            logger.warning(f"Unknown portnum value: {portnum}")
            return f"UNKNOWN_PORTNUM_{portnum}"

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

            print(f"\n{'=' * SEPARATOR_WIDTH}")
            print(f"Topic: {msg.topic}")
            print(f"From: {gateway_id} → To: !ffffffff")
            print(f"Gateway: {gateway_id}, Channel: unknown")
            print(f"Packet ID: 0x00000000")
            print(f"{'─' * SEPARATOR_WIDTH}")
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

            print(f"{'=' * SEPARATOR_WIDTH}")
            return True
        except Exception:
            return False

    def _handle_service_envelope(self, msg, raw_dump_text: str | None = None):
        """Handle ServiceEnvelope MQTT messages."""
        logger.debug(f"Handling ServiceEnvelope on topic: {msg.topic}")
        try:
            service_envelope = mqtt_pb2.ServiceEnvelope()
            service_envelope.ParseFromString(msg.payload)
        except Exception:
            logger.error(f"Error parsing ServiceEnvelope on topic: {msg.topic}, payload length: {len(msg.payload)} bytes")
            from .hex_dump import hex_dump
            dump = hex_dump(msg.payload, use_color=self.formatter.hex_dump_colored)
            logger.error(f"Payload dump:\n{dump}")
            return


        packet = service_envelope.packet
        channel_id = service_envelope.channel_id

        logger.debug(f"Packet fields: decoded={packet.HasField('decoded')}, encrypted={packet.HasField('encrypted')}")
        if packet.HasField('decoded'):
            try:
                portnum_name = portnums_pb2.PortNum.Name(packet.decoded.portnum)
            except ValueError:
                portnum_name = f"UNKNOWN_{packet.decoded.portnum}"
            logger.debug(f"Decoded packet: portnum={packet.decoded.portnum} ({portnum_name})")

        data = None
        if packet.HasField('decoded'):
            data = packet.decoded
        elif packet.HasField('encrypted'):
            data = self.crypto.decrypt_packet(packet, channel_id, debug=False)
            if data:
                self.stats.successful_decrypts += 1
                logger.debug("Successfully decrypted packet")
            else:
                self.stats.failed_decrypts += 1
                logger.debug("Failed to decrypt packet")

                # Check if encrypted packets are filtered
                if self.message_filter.should_filter_encrypted():
                    logger.debug("Filtered out encrypted packet")
                    return

                packet_info = self.parser.parse_packet_info(packet)
                encrypted_data = bytes(packet.encrypted) if packet.HasField('encrypted') else None

                # Store encrypted packet to node database
                self.node_db.add_encrypted_packet(
                    packet_info.from_node_hex,
                    encrypted_data,
                    from_node=packet_info.from_node_hex,
                    to_node=packet_info.to_node_hex,
                    packet_id=packet_info.packet_id,
                    channel_id=channel_id
                )

                # If raw dump was requested, print it first, then the failure block
                failure = self.formatter.format_encrypted_failure(packet_info, encrypted_data)
                if raw_dump_text:
                    # Remove leading '=' line from failure to keep a single separator
                    first_nl = failure.find('\n')
                    if first_nl != -1 and failure[:first_nl] == ("=" * SEPARATOR_WIDTH):
                        failure = failure[first_nl+1:]
                    print(f"\n{raw_dump_text}\n{failure}\n")
                else:
                    print(f"\n{failure}\n")
                return

        parsed_msg = self.parser.create_parsed_message(msg, service_envelope, packet, data)

        if data:
            portnum_name = self._get_portnum_name(data.portnum)
            self.stats.increment_portnum(portnum_name)
            logger.info(f"Received {portnum_name} from {parsed_msg.packet_info.from_node_hex}")

            # Check if message type is filtered
            if self.message_filter.should_filter_portnum(portnum_name):
                logger.debug(f"Filtered out {portnum_name}")
                return

        # If this is a text message that looks like raw 'Salted__' bytes, try Base64-normalized decryption first,
        # then fall back to bytes-based decrypt (for this test, we keep both paths available).
        # If we successfully decrypt, also update node database entries so stored text is decrypted.
        try:
            from .models import TextMessage
            if isinstance(parsed_msg.content, TextMessage) and parsed_msg.content.is_openssl_encrypted and parsed_msg.content.is_salted_base64 is False:
                # The decoded payload bytes are available via decoded_payload_b64
                import base64
                if parsed_msg.decoded_payload_b64:
                    payload_bytes = base64.b64decode(parsed_msg.decoded_payload_b64)
                    # Normalize to Base64 and use Base64 decrypt path exclusively
                    payload_b64 = base64.b64encode(payload_bytes).decode('ascii')
                    decrypted = self.crypto.decrypt_openssl_salted(payload_b64)
                    if decrypted:
                        parsed_msg.content.text = decrypted
                        parsed_msg.content.decrypted = True
                        # Update node DB last message entries for from/to to store decrypted text
                        try:
                            from_node = parsed_msg.packet_info.from_node_hex
                            to_node = parsed_msg.packet_info.to_node_hex
                            # Update the most recent messages in both participants if present
                            self.node_db.update_last_message_text(from_node, original_text=None, new_text=decrypted)
                            if to_node and to_node != '!ffffffff':
                                self.node_db.update_last_message_text(to_node, original_text=None, new_text=decrypted)
                        except Exception:
                            pass
        except Exception:
            pass

        formatted = self.formatter.format_message(parsed_msg)
        # If content is text and SALTED filtering applies, skip printing
        try:
            from .models import TextMessage
            if isinstance(parsed_msg.content, TextMessage):
                is_salted = getattr(parsed_msg.content, 'is_openssl_encrypted', False)
                if self.message_filter.should_filter_salted(is_salted):
                    logger.debug("Filtered out SALTED text message (decoded path)")
                    return
        except Exception:
            pass
        if raw_dump_text:
            # The formatted block already has top+bottom '=' lines; we want exactly
            # one separator between raw and formatted. Since raw ended with '=',
            # strip the first line if it is a full-width '='.
            first_newline = formatted.find('\n')
            if first_newline != -1 and formatted[:first_newline] == ("=" * SEPARATOR_WIDTH):
                formatted = formatted[first_newline+1:]
            print(f"\n{raw_dump_text}\n{formatted}\n")
        else:
            print(f"\n{formatted}\n")

    def connect(self, use_listener_id: bool = False, subscribe: bool = True) -> bool:
        """
        Connect to MQTT broker.

        Args:
            use_listener_id: Use randomized listener client ID instead of node ID
            subscribe: Whether to subscribe to messages (False for publish-only)

        Returns:
            True if connected successfully, False otherwise
        """
        if use_listener_id:
            # Use a fully randomized listener client ID to avoid collisions
            # and any association with the node ID. Keep it short but unique
            # enough for MQTT brokers that have client ID length limits.
            import uuid
            rand = uuid.uuid4().hex[:8]
            client_id = f"!{rand}"
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
            # Prepare optional fixed salt if provided (hex string to bytes) and iterations
            fixed_salt = None
            fs_hex = getattr(self.client_config, 'openssl_fixed_salt', None)
            if fs_hex:
                try:
                    fixed_salt = bytes.fromhex(fs_hex)
                except ValueError:
                    fixed_salt = None
            openssl_iters = getattr(self.client_config, 'openssl_pbkdf2_iter', 10000)

            self.publisher = MessagePublisher(
                self.client,
                self.node_config,
                self.server_config,
                self.crypto,
                self.formatter.hex_dump,
                self.formatter.hex_dump_colored,
                self.crypto.openssl_password,
                getattr(self.client_config, 'openssl_send_base64', False),
                openssl_iters,
                fixed_salt
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

        # Shutdown node database and flush pending writes
        self.node_db.shutdown()

    def __enter__(self):
        """Enter context manager."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager and disconnect."""
        self.disconnect()
        return False

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

    def send_position_message(self, to_node_id: str, channel: int = 0, hop_limit: int = 3, randomize: bool = False) -> bool:
        """Send position to a specific node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        if not self.publisher:
            print("Publisher not initialized")
            return False

        result = self.publisher.send_position_message(to_node_id, channel, hop_limit, randomize)

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
