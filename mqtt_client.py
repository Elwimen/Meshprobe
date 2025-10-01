#!/usr/bin/env python3
"""
Meshtastic MQTT Client
Connects to MQTT server and can publish position to map and send messages to nodes.
"""

import json
import sys
import argparse
import time
from pathlib import Path
import paho.mqtt.client as mqtt

try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

try:
    from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, config_pb2, telemetry_pb2
    from meshtastic.protobuf import mesh_pb2 as mesh_protobuf
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: cryptography package not found. Install with: pip install cryptography")
    sys.exit(1)

import base64
import hashlib
from datetime import datetime, timezone
import struct
import random


class MeshtasticMQTTClient:
    def __init__(self, server_config_path, node_config_path, log_file="mqtt_messages.json", openssl_password=None):
        self.server_config = self.load_json(server_config_path)
        self.node_config = self.load_json(node_config_path)
        self.client = None
        self.connected = False
        self.log_file = log_file
        self.message_log = []
        self.openssl_password = openssl_password

        # Statistics tracking
        self.stats = {
            'total_messages': 0,
            'successful_decrypts': 0,
            'failed_decrypts': 0,
            'parse_errors': 0,
            'portnum_counts': {}
        }

        # Calculate node num from id if not present
        self._ensure_node_num()

        # Load channel PSKs (Pre-Shared Keys) for decryption
        self.channel_keys = self.load_channel_keys()

    @staticmethod
    def load_json(path):
        """Load JSON configuration file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Config file not found: {path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {path}: {e}")
            sys.exit(1)

    def _ensure_node_num(self):
        """Calculate node num from id if not present."""
        node_id_config = self.node_config.get('node_id', {})
        if isinstance(node_id_config, dict):
            node_id_str = node_id_config.get('id', '')
            if node_id_str.startswith('!'):
                node_num = int(node_id_str[1:], 16)
                node_id_config['num'] = node_num
            elif 'num' not in node_id_config:
                print("Error: node_id must have either 'id' field starting with ! or 'num' field")
                sys.exit(1)

    def load_channel_keys(self):
        """Load channel PSKs for decryption."""
        channels = self.node_config.get('channels', {})
        if not channels:
            # Default: use the well-known default PSK from Channels.h:144-145
            # This is the 16-byte AES128 key used for default channels
            default_key = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])
            return {"default": default_key}

        keys = {}
        for channel_name, channel_config in channels.items():
            psk_b64 = channel_config.get('psk')
            if psk_b64:
                keys[channel_name] = base64.b64decode(psk_b64)
            else:
                # Use default PSK if not specified
                keys[channel_name] = bytes([0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
                                           0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01])

        return keys

    def calculate_channel_hash(self, psk):
        """Calculate channel hash from PSK (first byte of SHA256)."""
        hash_val = hashlib.sha256(psk).digest()[0]
        return hash_val

    def decrypt_openssl_salted(self, ciphertext_b64):
        """Decrypt OpenSSL 'Salted__' format (AES-256-CBC with password)."""
        if not self.openssl_password:
            return None

        try:
            # Decode base64
            data = base64.b64decode(ciphertext_b64)

            # Check for "Salted__" magic
            if not data.startswith(b'Salted__'):
                return None

            # Extract salt (8 bytes after "Salted__")
            salt = data[8:16]
            ciphertext = data[16:]

            # Derive key and IV using EVP_BytesToKey (same as OpenSSL)
            # This mimics: openssl enc -aes-256-cbc -d -a -pbkdf2
            # But older versions use MD5-based derivation, so we try both

            # Try PBKDF2 first (modern OpenSSL default)
            try:
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=48,  # 32 bytes key + 16 bytes IV
                    salt=salt,
                    iterations=10000,
                    backend=default_backend()
                )
                key_iv = kdf.derive(self.openssl_password.encode('utf-8'))
                key = key_iv[:32]
                iv = key_iv[32:48]
            except:
                # Fall back to MD5-based derivation (old OpenSSL)
                def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
                    m = []
                    i = 0
                    while len(b''.join(m)) < (key_len + iv_len):
                        md = hashlib.md5()
                        data = password.encode('utf-8') + salt
                        if i > 0:
                            data = m[i - 1] + data
                        md.update(data)
                        m.append(md.digest())
                        i += 1
                    ms = b''.join(m)
                    return ms[:key_len], ms[key_len:key_len + iv_len]

                key, iv = evp_bytes_to_key(self.openssl_password, salt)

            # Decrypt using AES-256-CBC
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_len = plaintext_padded[-1]
            plaintext = plaintext_padded[:-padding_len]

            return plaintext.decode('utf-8', errors='replace')
        except Exception as e:
            print(f"   [OpenSSL decrypt failed: {e}]")
            return None

    def decrypt_packet(self, packet, channel_id, debug=False):
        """Decrypt an encrypted packet using the channel PSK."""
        if not packet.HasField('encrypted'):
            return None

        # Get the encryption key for this channel
        key = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        if not key:
            return None

        # Handle key length for AES
        # Meshtastic uses AES-128 (16 bytes) for default PSK, AES-256 (32 bytes) for custom PSKs
        if len(key) == 16:
            # AES-128 - use as is
            pass
        elif len(key) == 32:
            # AES-256 - use as is
            pass
        elif len(key) < 16:
            # Pad to 16 bytes for AES-128
            key = key + b'\x00' * (16 - len(key))
        elif len(key) < 32:
            # Pad to 32 bytes for AES-256
            key = key + b'\x00' * (32 - len(key))
        else:
            # Truncate to 32 bytes
            key = key[:32]

        # Extract encrypted data
        encrypted_data = bytes(packet.encrypted)

        # Meshtastic uses AES-256-CTR encryption
        # The nonce/IV is 16 bytes: packet_id (8 bytes LE) + from_node (4 bytes LE) + zeros (4 bytes)
        # See CryptoEngine.cpp:259-268
        packet_id = packet.id
        from_node = getattr(packet, 'from')

        # Create 16-byte nonce for AES-CTR
        nonce = bytearray(16)
        nonce[0:8] = packet_id.to_bytes(8, byteorder='little')
        nonce[8:12] = from_node.to_bytes(4, byteorder='little')
        # nonce[12:16] remains zeros (used for extraNonce in PKI mode)

        if debug:
            print(f"Debug: packet_id={packet_id:#x}, from_node={from_node:#x}")
            print(f"Debug: nonce={nonce.hex()}")
            print(f"Debug: key={key.hex()}")
            print(f"Debug: encrypted_len={len(encrypted_data)}")
            print(f"Debug: encrypted_first_16={encrypted_data[:16].hex()}")

        # Decrypt using AES-CTR
        cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(nonce)), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

        if debug:
            print(f"Debug: decrypted_len={len(decrypted)}")
            print(f"Debug: decrypted_first_32={decrypted[:min(32, len(decrypted))].hex()}")

        # Parse decrypted data as Data protobuf
        try:
            data = mesh_pb2.Data()
            data.ParseFromString(decrypted)
            return data
        except Exception as e:
            if debug:
                print(f"Failed to parse decrypted data: {e}")
                print(f"Full decrypted hex: {decrypted.hex()}")
            return None

    def on_connect(self, client, userdata, flags, rc):
        """Callback when connected to MQTT broker."""
        if rc == 0:
            print(f"Connected to MQTT broker at {self.server_config['host']}:{self.server_config['port']}")
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

    def log_message_to_file(self, msg, service_envelope, packet, data=None):
        """Log received message to JSON file with detailed decoded information."""
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        # Build packet info
        from_node = getattr(packet, 'from')
        hop_limit = packet.hop_limit if hasattr(packet, 'hop_limit') else 0
        hop_start = packet.hop_start if hasattr(packet, 'hop_start') else 0

        log_entry = {
            "timestamp": timestamp,
            "topic": msg.topic,
            "channel_id": service_envelope.channel_id,
            "gateway_id": service_envelope.gateway_id,
            "packet": {
                "from": f"!{from_node:08x}",
                "from_decimal": from_node,
                "to": f"!{packet.to:08x}",
                "to_decimal": packet.to,
                "id": f"0x{packet.id:08x}",
                "id_decimal": packet.id,
                "channel_hash": packet.channel if hasattr(packet, 'channel') else 0,
                "hop_limit": hop_limit,
                "hop_start": hop_start,
                "hops_away": hop_start - hop_limit if hop_start > 0 else 0,
                "via_mqtt": packet.via_mqtt if hasattr(packet, 'via_mqtt') else False,
                "want_ack": packet.want_ack if hasattr(packet, 'want_ack') else False,
            },
            "encrypted": packet.HasField('encrypted'),
            "encrypted_payload_b64": base64.b64encode(bytes(packet.encrypted)).decode('utf-8') if packet.HasField('encrypted') else None,
            "decoded_payload_b64": base64.b64encode(packet.decoded.payload).decode('utf-8') if packet.HasField('decoded') else None,
            "decoded": None
        }

        # Add detailed decoded information
        if data:
            portnum = data.portnum
            payload = data.payload

            decoded_info = {
                "portnum": portnum,
                "portnum_name": portnums_pb2.PortNum.Name(portnum),
                "payload_b64": base64.b64encode(payload).decode('utf-8'),
                "payload_length": len(payload),
                "content": None
            }

            try:
                if portnum == portnums_pb2.TEXT_MESSAGE_APP:
                    text = payload.decode('utf-8', errors='replace')
                    decoded_info["content"] = {
                        "type": "text",
                        "text": text,
                        "is_openssl_encrypted": text.startswith('U2FsdGVk')
                    }

                elif portnum == portnums_pb2.POSITION_APP:
                    position = mesh_pb2.Position()
                    position.ParseFromString(payload)
                    decoded_info["content"] = {
                        "type": "position",
                        "latitude": position.latitude_i / 1e7,
                        "longitude": position.longitude_i / 1e7,
                        "altitude": position.altitude,
                        "time": position.time if position.time else None,
                        "precision_bits": position.precision_bits if hasattr(position, 'precision_bits') else None
                    }

                elif portnum == portnums_pb2.NODEINFO_APP:
                    user = mesh_pb2.User()
                    user.ParseFromString(payload)
                    decoded_info["content"] = {
                        "type": "nodeinfo",
                        "id": user.id if user.id else None,
                        "long_name": user.long_name if user.long_name else None,
                        "short_name": user.short_name if user.short_name else None,
                        "macaddr": ':'.join(f'{b:02X}' for b in user.macaddr) if user.macaddr else None,
                        "hw_model": user.hw_model if user.hw_model else None,
                        "hw_model_name": config_pb2.Config.DeviceConfig.HardwareModel.Name(user.hw_model) if user.hw_model else None
                    }

                elif portnum == portnums_pb2.TELEMETRY_APP:
                    telemetry = telemetry_pb2.Telemetry()
                    telemetry.ParseFromString(payload)
                    content = {"type": "telemetry"}

                    if telemetry.HasField('device_metrics'):
                        dm = telemetry.device_metrics
                        content["device_metrics"] = {
                            "battery_level": dm.battery_level if dm.battery_level else None,
                            "voltage": dm.voltage if dm.voltage else None,
                            "channel_utilization": dm.channel_utilization if dm.channel_utilization else None,
                            "air_util_tx": dm.air_util_tx if dm.air_util_tx else None,
                            "uptime_seconds": dm.uptime_seconds if dm.uptime_seconds else None
                        }
                    elif telemetry.HasField('environment_metrics'):
                        em = telemetry.environment_metrics
                        content["environment_metrics"] = {
                            "temperature": em.temperature if em.temperature else None,
                            "relative_humidity": em.relative_humidity if em.relative_humidity else None,
                            "barometric_pressure": em.barometric_pressure if em.barometric_pressure else None
                        }

                    decoded_info["content"] = content

                elif portnum == portnums_pb2.ROUTING_APP:
                    routing = mesh_pb2.Routing()
                    routing.ParseFromString(payload)
                    decoded_info["content"] = {
                        "type": "routing",
                        "error_reason": mesh_pb2.Routing.Error.Name(routing.error_reason) if routing.error_reason else "ACK"
                    }

                else:
                    decoded_info["content"] = {
                        "type": "unknown",
                        "portnum": portnum
                    }

            except Exception as e:
                decoded_info["content"] = {
                    "type": "parse_error",
                    "error": str(e)
                }

            log_entry["decoded"] = decoded_info

        self.message_log.append(log_entry)

        with open(self.log_file, 'w') as f:
            json.dump(self.message_log, f, indent=2)

    def on_message(self, client, userdata, msg):
        """Callback when message is received."""
        self.stats['total_messages'] += 1

        # Skip JSON messages - we only handle protobuf
        if '/json/' in msg.topic:
            return

        # Handle MAP REPORT messages on /map/ topics
        # These might be ServiceEnvelopes or direct MapReports depending on presence of gateway ID
        # Topic format: msh/{region}/{country}/2/map/ or msh/{region}/{country}/2/map/{gateway}
        topic_parts = msg.topic.split('/')
        if len(topic_parts) >= 5 and topic_parts[-2] == 'map':
            # If last part is empty (topic ends with /map/), it's a ServiceEnvelope
            if not topic_parts[-1]:
                # Fall through to normal ServiceEnvelope handling
                pass
            else:
                # Has gateway ID, try direct MapReport
                try:
                    map_report = mqtt_pb2.MapReport()
                    map_report.ParseFromString(msg.payload)

                    print(f"\n{'='*60}")
                    print(f"Topic: {msg.topic}")
                    gateway_id = topic_parts[-1]
                    print(f"From: {gateway_id} → To: !ffffffff")
                    print(f"Gateway: {gateway_id}, Channel: unknown")
                    print(f"Packet ID: 0x00000000")
                    print(f"{'─'*60}")
                    print(f"🗺️  MAP REPORT")
                    print(f"   Long name:  {map_report.long_name}")
                    print(f"   Short name: {map_report.short_name}")
                    lat = map_report.latitude_i / 1e7
                    lon = map_report.longitude_i / 1e7
                    print(f"   Position:   {lat:.6f}, {lon:.6f}, {map_report.altitude}m")
                    print(f"   Firmware:   {map_report.firmware_version}")
                    if map_report.region:
                        region_name = config_pb2.Config.LoRaConfig.RegionCode.Name(map_report.region)
                        print(f"   Region:     {region_name}")
                    if map_report.modem_preset:
                        preset_name = config_pb2.Config.LoRaConfig.ModemPreset.Name(map_report.modem_preset)
                        print(f"   Modem:      {preset_name}")
                    print(f"{'='*60}")
                    return
                except Exception as e:
                    print(f"Error decoding direct MAP REPORT on topic: {msg.topic}")
                    return

        try:
            # Decode ServiceEnvelope
            service_envelope = mqtt_pb2.ServiceEnvelope()
            try:
                service_envelope.ParseFromString(msg.payload)
            except Exception as parse_error:
                print(f"Error parsing ServiceEnvelope on topic: {msg.topic}")
                print(f"Payload length: {len(msg.payload)} bytes")
                return

            packet = service_envelope.packet
            channel_id = service_envelope.channel_id
            gateway_id = service_envelope.gateway_id

            # Get sender node ID
            from_node = getattr(packet, 'from')
            to_node = packet.to

            # Get hop information
            hop_limit = packet.hop_limit if hasattr(packet, 'hop_limit') else 0
            hop_start = packet.hop_start if hasattr(packet, 'hop_start') else 0
            hops_away = hop_start - hop_limit if hop_start > 0 else 0
            via_mqtt = packet.via_mqtt if hasattr(packet, 'via_mqtt') else False
            want_ack = packet.want_ack if hasattr(packet, 'want_ack') else False

            print(f"\n{'='*60}")
            print(f"Topic: {msg.topic}")
            print(f"From: !{from_node:08x} → To: !{to_node:08x}")
            print(f"Gateway: {gateway_id}, Channel: {channel_id}")
            if hops_away > 0:
                print(f"Hops: {hops_away} away (limit={hop_limit}, start={hop_start})")
            if via_mqtt:
                print(f"Via: MQTT")
            if want_ack:
                print(f"Want ACK: Yes")
            print(f"Packet ID: 0x{packet.id:08x}")

            # Try to decode or decrypt the message
            data = None
            if packet.HasField('decoded'):
                data = packet.decoded
            elif packet.HasField('encrypted'):
                data = self.decrypt_packet(packet, channel_id, debug=False)
                if data:
                    self.stats['successful_decrypts'] += 1
                else:
                    self.stats['failed_decrypts'] += 1
                    print(f"{'─'*60}")
                    print(f"🔒 ENCRYPTED (unable to decrypt)")
                    print(f"{'='*60}\n")
                    return

            # Log message to file
            self.log_message_to_file(msg, service_envelope, packet, data)

            if data:
                portnum = data.portnum
                payload = data.payload

                # Track portnum statistics
                portnum_name = portnums_pb2.PortNum.Name(portnum)
                self.stats['portnum_counts'][portnum_name] = self.stats['portnum_counts'].get(portnum_name, 0) + 1

                print(f"─" * 60)
                if portnum == portnums_pb2.TEXT_MESSAGE_APP:
                    text = payload.decode('utf-8', errors='replace')
                    print(f"💬 TEXT MESSAGE")

                    # Try to decrypt OpenSSL salted messages
                    if text.startswith('U2FsdGVk'):  # base64 for "Salted__"
                        decrypted = self.decrypt_openssl_salted(text)
                        if decrypted:
                            print(f"   🔓 {decrypted}")
                        else:
                            print(f"   🔒 {text}")
                            if self.openssl_password:
                                print(f"   (Failed to decrypt with provided password)")
                            else:
                                print(f"   (Encrypted with OpenSSL - use --openssl-password to decrypt)")
                    else:
                        print(f"   {text}")
                elif portnum == portnums_pb2.POSITION_APP:
                    position = mesh_pb2.Position()
                    position.ParseFromString(payload)
                    lat = position.latitude_i / 1e7
                    lon = position.longitude_i / 1e7
                    alt = position.altitude
                    print(f"📍 POSITION")
                    print(f"   Latitude:  {lat:.6f}°")
                    print(f"   Longitude: {lon:.6f}°")
                    print(f"   Altitude:  {alt}m")
                    if position.time:
                        from datetime import datetime
                        ts = datetime.fromtimestamp(position.time, tz=timezone.utc)
                        print(f"   Time:      {ts.isoformat()}")
                elif portnum == portnums_pb2.NODEINFO_APP:
                    user = mesh_pb2.User()
                    user.ParseFromString(payload)
                    print(f"ℹ️  NODE INFO")
                    print(f"   Long name:  {user.long_name}")
                    print(f"   Short name: {user.short_name}")
                    if user.id:
                        print(f"   Node ID:    {user.id}")
                    if user.macaddr:
                        mac = ':'.join(f'{b:02X}' for b in user.macaddr)
                        print(f"   MAC:        {mac}")
                    if user.hw_model:
                        try:
                            hw_name = mesh_pb2.HardwareModel.Name(user.hw_model)
                            print(f"   Hardware:   {hw_name}")
                        except:
                            print(f"   Hardware:   {user.hw_model} (unknown)")
                elif portnum == portnums_pb2.TELEMETRY_APP:
                    telemetry = telemetry_pb2.Telemetry()
                    telemetry.ParseFromString(payload)
                    if telemetry.HasField('device_metrics'):
                        dm = telemetry.device_metrics
                        print(f"📊 DEVICE TELEMETRY")
                        if dm.battery_level > 0 and dm.battery_level <= 100:
                            print(f"   Battery:    {dm.battery_level:.0f}%")
                        elif dm.battery_level == 101:
                            print(f"   Battery:    Plugged in")
                        if dm.voltage > 0:
                            print(f"   Voltage:    {dm.voltage:.2f}V")
                        if dm.channel_utilization > 0:
                            print(f"   Ch. Util:   {dm.channel_utilization:.1f}%")
                        if dm.air_util_tx > 0:
                            print(f"   Air TX:     {dm.air_util_tx:.1f}%")
                        if dm.uptime_seconds > 0:
                            hours = dm.uptime_seconds // 3600
                            minutes = (dm.uptime_seconds % 3600) // 60
                            print(f"   Uptime:     {hours}h {minutes}m")
                    elif telemetry.HasField('environment_metrics'):
                        em = telemetry.environment_metrics
                        print(f"🌡️  ENVIRONMENT TELEMETRY")
                        if em.temperature != 0:
                            print(f"   Temperature: {em.temperature:.1f}°C")
                        if em.relative_humidity != 0:
                            print(f"   Humidity:    {em.relative_humidity:.1f}%")
                        if em.barometric_pressure != 0:
                            print(f"   Pressure:    {em.barometric_pressure:.1f} hPa")
                    else:
                        print(f"📊 TELEMETRY")
                        print(f"   (Unknown telemetry type)")
                elif portnum == portnums_pb2.ROUTING_APP:
                    routing = mesh_pb2.Routing()
                    routing.ParseFromString(payload)
                    print(f"🔄 ROUTING")
                    if routing.error_reason:
                        err_name = mesh_pb2.Routing.Error.Name(routing.error_reason)
                        print(f"   Type: {err_name}")
                    else:
                        print(f"   Type: ACK")
                elif portnum == portnums_pb2.ADMIN_APP:
                    print(f"🔧 ADMIN PACKET")
                elif portnum == portnums_pb2.TRACEROUTE_APP:
                    print(f"🗺️  TRACEROUTE")
                elif portnum == portnums_pb2.NEIGHBORINFO_APP:
                    neighbor_info = mesh_pb2.NeighborInfo()
                    neighbor_info.ParseFromString(payload)
                    print(f"🔗 NEIGHBOR INFO")
                    print(f"   Reporter:   !{neighbor_info.node_id:08x}")
                    if neighbor_info.last_sent_by_id != neighbor_info.node_id:
                        print(f"   Via:        !{neighbor_info.last_sent_by_id:08x}")
                    if neighbor_info.node_broadcast_interval_secs > 0:
                        print(f"   Interval:   {neighbor_info.node_broadcast_interval_secs}s")
                    print(f"   Neighbors:  {len(neighbor_info.neighbors)}")
                    for nbr in neighbor_info.neighbors:
                        print(f"     - !{nbr.node_id:08x} SNR: {nbr.snr:.1f}dB")
                elif portnum == portnums_pb2.MAP_REPORT_APP:
                    map_report = mqtt_pb2.MapReport()
                    map_report.ParseFromString(payload)
                    print(f"🗺️  MAP REPORT")
                    print(f"   Long name:  {map_report.long_name}")
                    print(f"   Short name: {map_report.short_name}")
                    lat = map_report.latitude_i / 1e7
                    lon = map_report.longitude_i / 1e7
                    print(f"   Position:   {lat:.6f}, {lon:.6f}, {map_report.altitude}m")
                    print(f"   Firmware:   {map_report.firmware_version}")
                    if map_report.region:
                        region_name = config_pb2.Config.LoRaConfig.RegionCode.Name(map_report.region)
                        print(f"   Region:     {region_name}")
                    if map_report.modem_preset:
                        preset_name = config_pb2.Config.LoRaConfig.ModemPreset.Name(map_report.modem_preset)
                        print(f"   Modem:      {preset_name}")
                else:
                    print(f"📦 PORTNUM {portnum}")
                    print(f"   Payload: {len(payload)} bytes")
            else:
                print(f"Unable to decode message")

            print(f"{'='*60}\n")

        except Exception as e:
            self.stats['parse_errors'] += 1
            print(f"Error decoding message: {e}")

    def connect(self, use_listener_id=False):
        """Connect to MQTT broker."""
        if use_listener_id:
            base_id = self.node_config['node_id']['id']
            hashed_id = hashlib.sha256(f"{base_id}-listener".encode()).hexdigest()[:8]
            client_id = f"!{hashed_id}"
        else:
            client_id = self.node_config['node_id']['id']
        self.client = mqtt.Client(client_id=client_id)
        self.client.username_pw_set(
            self.server_config['username'],
            self.server_config['password']
        )

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.on_publish = self.on_publish
        self.client.on_message = self.on_message

        try:
            print(f"Connecting to {self.server_config['host']}:{self.server_config['port']}...")
            if use_listener_id:
                print(f"Using listener client ID: {client_id}")
            self.client.connect(
                self.server_config['host'],
                self.server_config['port'],
                60
            )
            self.client.loop_start()

            # Wait for connection
            timeout = 10
            start = time.time()
            while not self.connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if not self.connected:
                print("Connection timeout")
                return False

            # Subscribe to all messages under root topic
            root_topic = self.server_config.get('root_topic', 'msh')
            subscribe_topic = f"{root_topic}/#"
            print(f"Subscribing to: {subscribe_topic}")
            self.client.subscribe(subscribe_topic, qos=1)

            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect(self):
        """Disconnect from MQTT broker."""
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def print_stats(self):
        """Print statistics summary."""
        print(f"\n{'='*60}")
        print(f"STATISTICS SUMMARY")
        print(f"{'='*60}")
        print(f"Total messages:       {self.stats['total_messages']}")
        print(f"Parse errors:         {self.stats['parse_errors']}")
        print(f"Successful decrypts:  {self.stats['successful_decrypts']}")
        print(f"Failed decrypts:      {self.stats['failed_decrypts']}")

        if self.stats['portnum_counts']:
            print(f"\nMessages by PortNum:")
            sorted_portnums = sorted(self.stats['portnum_counts'].items(), key=lambda x: x[1], reverse=True)
            for portnum_name, count in sorted_portnums:
                print(f"  {portnum_name:25s} {count:5d}")
        print(f"{'='*60}\n")

    def publish_map_position(self):
        """Publish position to the mesh map using protobuf MapReport."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        root = self.server_config.get('root_topic', 'msh')
        topic = f"{root}/2/map/"

        # Gaussian randomize position within ±0.0025 degrees
        base_lat = self.node_config['position']['latitude']
        base_lon = self.node_config['position']['longitude']
        base_alt = self.node_config['position']['altitude']

        randomized_lat = random.gauss(base_lat, 0.0025 / 3)
        randomized_lon = random.gauss(base_lon, 0.0025 / 3)
        randomized_alt = random.gauss(base_alt + 100, 100 / 3)

        randomized_lat = max(base_lat - 0.0025, min(base_lat + 0.0025, randomized_lat))
        randomized_lon = max(base_lon - 0.0025, min(base_lon + 0.0025, randomized_lon))
        randomized_alt = max(base_alt, min(base_alt + 200, randomized_alt))

        # Calculate latitude_i and longitude_i (multiply by 1e7)
        lat_i = int(randomized_lat * 1e7)
        lon_i = int(randomized_lon * 1e7)

        # Apply position precision (default 14)
        position_precision = self.node_config['position'].get('precision', 14)
        lat_i = (lat_i & (0xFFFFFFFF << (32 - position_precision))) + (1 << (31 - position_precision))
        lon_i = (lon_i & (0xFFFFFFFF << (32 - position_precision))) + (1 << (31 - position_precision))

        # Get region enum value
        region_config = self.node_config.get('region', {})
        region_name = region_config.get('value', 'UNSET') if isinstance(region_config, dict) else region_config
        region = getattr(config_pb2.Config.LoRaConfig, region_name, config_pb2.Config.LoRaConfig.UNSET)

        # Get modem preset enum value
        modem_preset_config = self.node_config.get('modem_preset', {})
        modem_preset_name = modem_preset_config.get('value', 'LONG_FAST') if isinstance(modem_preset_config, dict) else modem_preset_config
        modem_preset = getattr(config_pb2.Config.LoRaConfig, modem_preset_name, config_pb2.Config.LoRaConfig.LONG_FAST)

        # Create MapReport
        map_report = mqtt_pb2.MapReport()
        map_report.long_name = self.node_config['long_name']
        map_report.short_name = self.node_config['short_name']

        # Get role value
        role_config = self.node_config.get('role', {})
        map_report.role = role_config.get('value', 0) if isinstance(role_config, dict) else role_config

        # Get hw_model value
        hw_model_config = self.node_config.get('hw_model', {})
        map_report.hw_model = hw_model_config.get('value', 0) if isinstance(hw_model_config, dict) else hw_model_config

        map_report.firmware_version = self.node_config.get('firmware_version', '2.5.0.simulated')
        map_report.region = region
        map_report.modem_preset = modem_preset
        map_report.has_default_channel = self.node_config.get('has_default_channel', True)
        map_report.latitude_i = lat_i
        map_report.longitude_i = lon_i
        map_report.altitude = int(randomized_alt)
        map_report.position_precision = position_precision
        map_report.num_online_local_nodes = 1
        map_report.has_opted_report_location = True

        # Create MeshPacket with MapReport
        mesh_packet = mesh_pb2.MeshPacket()
        setattr(mesh_packet, 'from', self.node_config['node_id']['num'])
        mesh_packet.to = 0xFFFFFFFF  # Broadcast
        mesh_packet.id = int(time.time()) & 0xFFFFFFFF
        mesh_packet.decoded.portnum = portnums_pb2.MAP_REPORT_APP
        mesh_packet.decoded.payload = map_report.SerializeToString()

        # Wrap in ServiceEnvelope
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)

        # Get channel_id value
        channel_config = self.node_config.get('channel', self.node_config.get('channel_id', {}))
        channel_id = channel_config.get('value', 'LongFast') if isinstance(channel_config, dict) else channel_config
        service_envelope.channel_id = channel_id
        service_envelope.gateway_id = self.node_config['node_id']['id']

        # Serialize and publish
        payload = service_envelope.SerializeToString()

        print(f"Publishing map report to topic: {topic}")
        print(f"Node: {self.node_config['long_name']} ({self.node_config['node_id']['id']})")
        print(f"Short name: {self.node_config['short_name']}")
        print(f"Position: {randomized_lat:.6f}, {randomized_lon:.6f}, {randomized_alt:.1f}m (randomized)")
        print(f"Precision: {position_precision} bits")
        print(f"Region: {region_name}, Modem: {modem_preset_name}")
        print(f"Firmware: {self.node_config.get('firmware_version', '2.5.0.simulated')}")
        print(f"Hardware: {hw_model_config.get('value', 0) if isinstance(hw_model_config, dict) else hw_model_config}")
        print(f"Role: {role_config.get('value', 0) if isinstance(role_config, dict) else role_config}")
        print(f"Channel: {channel_id}, Default channel: {self.node_config.get('has_default_channel', True)}")
        print(f"Payload size: {len(payload)} bytes")

        result = self.client.publish(topic, payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_text_message(self, text, to_node_id, channel=0, hop_limit=3):
        """Send a text message to a specific node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        # Convert hex ID to node number
        to_node_num = int(to_node_id, 16) if isinstance(to_node_id, str) else to_node_id

        root = self.server_config.get('root_topic', 'msh')

        # Get channel_id value
        channel_config = self.node_config.get('channel', self.node_config.get('channel_id', {}))
        channel_id = channel_config.get('value', 'LongFast') if isinstance(channel_config, dict) else channel_config

        topic = f"{root}/2/e/{channel_id}/{self.node_config['node_id']['id']}"

        # Calculate channel hash from PSK
        psk = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        channel_hash = self.calculate_channel_hash(psk) if channel == 0 else channel

        # Create MeshPacket with text message
        mesh_packet = mesh_pb2.MeshPacket()
        setattr(mesh_packet, 'from', self.node_config['node_id']['num'])
        mesh_packet.to = to_node_num
        mesh_packet.id = int(time.time()) & 0xFFFFFFFF
        mesh_packet.channel = channel_hash
        mesh_packet.hop_limit = hop_limit
        mesh_packet.want_ack = False
        mesh_packet.decoded.portnum = portnums_pb2.TEXT_MESSAGE_APP
        mesh_packet.decoded.payload = text.encode('utf-8')

        # Wrap in ServiceEnvelope
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)
        service_envelope.channel_id = channel_id
        service_envelope.gateway_id = self.node_config['node_id']['id']

        # Serialize and publish
        payload = service_envelope.SerializeToString()

        print(f"Sending text message to node !{to_node_id} (decimal: {to_node_num})")
        print(f"Topic: {topic}")
        print(f"Message: {text}")
        print(f"Payload size: {len(payload)} bytes")

        result = self.client.publish(topic, payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS

    def send_position_message(self, to_node_id, channel=0, hop_limit=3):
        """Send position to a specific node."""
        if not self.connected:
            print("Not connected to MQTT broker")
            return False

        # Convert hex ID to node number
        to_node_num = int(to_node_id, 16) if isinstance(to_node_id, str) else to_node_id

        root = self.server_config.get('root_topic', 'msh')

        # Get channel_id value
        channel_config = self.node_config.get('channel', self.node_config.get('channel_id', {}))
        channel_id = channel_config.get('value', 'LongFast') if isinstance(channel_config, dict) else channel_config

        topic = f"{root}/2/e/{channel_id}/{self.node_config['node_id']['id']}"

        # Calculate channel hash from PSK
        psk = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        channel_hash = self.calculate_channel_hash(psk) if channel == 0 else channel

        # Create Position protobuf
        lat_i = int(self.node_config['position']['latitude'] * 1e7)
        lon_i = int(self.node_config['position']['longitude'] * 1e7)

        position = mesh_pb2.Position()
        position.latitude_i = lat_i
        position.longitude_i = lon_i
        position.altitude = int(self.node_config['position']['altitude'])
        position.time = int(time.time())

        # Create MeshPacket with position
        mesh_packet = mesh_pb2.MeshPacket()
        setattr(mesh_packet, 'from', self.node_config['node_id']['num'])
        mesh_packet.to = to_node_num
        mesh_packet.id = int(time.time()) & 0xFFFFFFFF
        mesh_packet.channel = channel_hash
        mesh_packet.hop_limit = hop_limit
        mesh_packet.want_ack = False
        mesh_packet.decoded.portnum = portnums_pb2.POSITION_APP
        mesh_packet.decoded.payload = position.SerializeToString()

        # Wrap in ServiceEnvelope
        service_envelope = mqtt_pb2.ServiceEnvelope()
        service_envelope.packet.CopyFrom(mesh_packet)
        service_envelope.channel_id = channel_id
        service_envelope.gateway_id = self.node_config['node_id']['id']

        # Serialize and publish
        payload = service_envelope.SerializeToString()

        print(f"Sending position to node !{to_node_id} (decimal: {to_node_num})")
        print(f"Topic: {topic}")
        print(f"Position: {self.node_config['position']['latitude']}, {self.node_config['position']['longitude']}")
        print(f"Payload size: {len(payload)} bytes")

        result = self.client.publish(topic, payload, qos=0)
        return result.rc == mqtt.MQTT_ERR_SUCCESS


def create_default_configs():
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

    server_path = Path("server_config.json")
    node_path = Path("node_config.json")

    if not server_path.exists():
        with open(server_path, 'w') as f:
            json.dump(server_config, f, indent=2)
        print(f"Created default server config: {server_path}")

    if not node_path.exists():
        with open(node_path, 'w') as f:
            json.dump(node_config, f, indent=2)
        print(f"Created default node config: {node_path}")


def main():
    parser = argparse.ArgumentParser(description='Meshtastic MQTT Client')
    parser.add_argument('--server-config', default='server_config.json',
                       help='Path to server configuration file')
    parser.add_argument('--node-config', default='node_config.json',
                       help='Path to node configuration file')
    parser.add_argument('--root-topic', type=str,
                       help='Override MQTT root topic (e.g., msh, msh/EU_868/HR)')
    parser.add_argument('--create-configs', action='store_true',
                       help='Create default configuration files')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Map position command
    subparsers.add_parser('map', help='Publish position to mesh map')

    # Send text message command
    text_parser = subparsers.add_parser('text', help='Send text message to a node')
    text_parser.add_argument('to_node', help='Target node hex ID (without ! prefix)')
    text_parser.add_argument('message', help='Message text')
    text_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    text_parser.add_argument('--hops', type=int, default=3, help='Hop limit')

    # Send position command
    pos_parser = subparsers.add_parser('position', help='Send position to a node')
    pos_parser.add_argument('to_node', help='Target node hex ID (without ! prefix)')
    pos_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    pos_parser.add_argument('--hops', type=int, default=3, help='Hop limit')

    # Listen command
    listen_parser = subparsers.add_parser('listen', help='Listen for incoming messages on MQTT')
    listen_parser.add_argument('--duration', type=int, default=0, help='Duration in seconds (0 = forever)')
    listen_parser.add_argument('--log-file', default='mqtt_messages.json', help='File to log messages to')
    listen_parser.add_argument('--openssl-password', type=str, help='Password to decrypt OpenSSL-encrypted messages')

    if ARGCOMPLETE_AVAILABLE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.create_configs:
        create_default_configs()
        return

    if not args.command:
        parser.print_help()
        return

    log_file = args.log_file if args.command == 'listen' and hasattr(args, 'log_file') else 'mqtt_messages.json'
    openssl_password = args.openssl_password if args.command == 'listen' and hasattr(args, 'openssl_password') else None
    client = MeshtasticMQTTClient(args.server_config, args.node_config, log_file, openssl_password)

    # Override root topic if specified
    if args.root_topic:
        client.server_config['root_topic'] = args.root_topic
        print(f"Overriding root topic to: {args.root_topic}")

    use_listener_id = (args.command == 'listen')
    if not client.connect(use_listener_id=use_listener_id):
        print("Failed to connect to MQTT broker")
        sys.exit(1)

    try:
        if args.command == 'map':
            client.publish_map_position()
            time.sleep(1)  # Wait for publish to complete
        elif args.command == 'text':
            client.send_text_message(args.message, args.to_node, args.channel, args.hops)
            time.sleep(1)  # Wait for publish to complete
        elif args.command == 'position':
            client.send_position_message(args.to_node, args.channel, args.hops)
            time.sleep(1)  # Wait for publish to complete
        elif args.command == 'listen':
            print(f"Listening for messages...")
            print(f"Logging messages to: {client.log_file}")
            if args.duration > 0:
                print(f"Will listen for {args.duration} seconds")
                time.sleep(args.duration)
            else:
                print("Press Ctrl+C to stop")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping...")
                    print(f"Logged {len(client.message_log)} messages to {client.log_file}")
                    client.print_stats()

    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
