"""
Cryptography engine for Meshtastic messages.
Handles AES-CTR decryption (Meshtastic packets) and AES-CBC decryption (OpenSSL).
"""

import base64
import hashlib
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: cryptography package not found. Install with: pip install cryptography")
    import sys
    sys.exit(1)

try:
    from meshtastic import mesh_pb2
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic")
    import sys
    sys.exit(1)

from .logging_config import get_logger

logger = get_logger('crypto')


class CryptoEngine:
    """Handles encryption and decryption for Meshtastic messages."""

    DEFAULT_PSK = bytes([
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01
    ])

    def __init__(self, channel_keys: dict[str, bytes], openssl_password: Optional[str] = None,
                 openssl_iterations: int = 10000):
        """
        Initialize CryptoEngine.

        Args:
            channel_keys: Dictionary mapping channel names to PSK bytes
            openssl_password: Optional password for OpenSSL-encrypted messages
        """
        self.channel_keys = channel_keys if channel_keys else {"default": self.DEFAULT_PSK}
        self.openssl_password = openssl_password
        self.openssl_iterations = int(openssl_iterations) if openssl_iterations else 10000
        self.channel_hash_to_key = self._build_hash_map()

    @staticmethod
    def xor_hash(data: bytes) -> int:
        """Calculate XOR hash of data (like firmware does)."""
        code = 0
        for byte in data:
            code ^= byte
        return code

    @staticmethod
    def calculate_channel_hash(channel_name: str, psk: bytes) -> int:
        """
        Calculate channel hash from channel name and PSK.
        This matches the firmware implementation in Channels.cpp:generateHash()

        Args:
            channel_name: Channel name string
            psk: Pre-shared key bytes

        Returns:
            Channel hash (0-255)
        """
        name_bytes = channel_name.encode('utf-8')
        h = CryptoEngine.xor_hash(name_bytes)
        h ^= CryptoEngine.xor_hash(psk)
        return h & 0xFF

    def _build_hash_map(self) -> dict[int, tuple[str, bytes]]:
        """Build mapping from channel hash to (channel_name, psk)."""
        hash_map = {}
        for channel_name, psk in self.channel_keys.items():
            channel_hash = self.calculate_channel_hash(channel_name, psk)
            hash_map[channel_hash] = (channel_name, psk)
            logger.debug(f"Channel '{channel_name}' -> hash 0x{channel_hash:02x}")
        return hash_map

    @staticmethod
    def load_channel_keys(channels: dict) -> dict[str, bytes]:
        """
        Load channel PSKs from configuration.
        Supports both formats:
        - Old: {"LongFast": {"psk": "AQ=="}}
        - New: {"0": {"name": "LongFast", "psk": "AQ=="}}

        Handles PSK index values (1-byte PSKs):
        - 0x00: No encryption (empty PSK)
        - 0x01: Use default Meshtastic PSK

        Args:
            channels: Dictionary of channel configurations

        Returns:
            Dictionary mapping channel names to PSK bytes
        """
        if not channels:
            return {"default": CryptoEngine.DEFAULT_PSK}

        keys = {}
        for key, channel_config in channels.items():
            if not isinstance(channel_config, dict):
                continue

            psk_b64 = channel_config.get('psk')
            if not psk_b64:
                continue

            psk_bytes = base64.b64decode(psk_b64)

            # Handle PSK index values (firmware compatibility)
            if len(psk_bytes) == 1:
                if psk_bytes[0] == 0:
                    # Index 0 = no encryption, skip this channel
                    logger.debug(f"Channel '{key}' has no encryption (PSK index 0), skipping")
                    continue
                elif psk_bytes[0] == 1:
                    # Index 1 = default PSK
                    psk_bytes = CryptoEngine.DEFAULT_PSK
                    logger.debug(f"Channel '{key}' using default PSK (index 1)")
                # else: treat as literal 1-byte PSK (will be zero-padded during encryption)

            # New format with index: {"0": {"name": "LongFast", "psk": "..."}}
            if key.isdigit() and 'name' in channel_config:
                channel_name = channel_config['name']
                keys[channel_name] = psk_bytes
                logger.debug(f"Loaded channel {key} -> '{channel_name}'")
            # Old format: {"LongFast": {"psk": "..."}}
            else:
                keys[key] = psk_bytes
                logger.debug(f"Loaded channel '{key}'")

        if not keys:
            keys["default"] = CryptoEngine.DEFAULT_PSK

        return keys

    def decrypt_packet(self, packet, channel_id: str, debug: bool = False) -> Optional[mesh_pb2.Data]:
        """
        Decrypt an encrypted Meshtastic packet using AES-CTR.
        Uses the channel hash from the packet to lookup the correct PSK.

        Args:
            packet: MeshPacket protobuf with encrypted field and channel hash
            channel_id: Channel ID from MQTT topic (informational, not used for crypto)
            debug: Enable debug output (deprecated, use logging instead)

        Returns:
            Decrypted Data protobuf or None if decryption fails
        """
        if not packet.HasField('encrypted'):
            return None

        channel_hash = packet.channel if hasattr(packet, 'channel') else 0
        logger.debug(f"Decrypting packet with channel hash 0x{channel_hash:02x} (topic channel: '{channel_id}')")

        # First try: Use channel hash to lookup the correct key
        if channel_hash in self.channel_hash_to_key:
            channel_name, key = self.channel_hash_to_key[channel_hash]
            logger.debug(f"Found channel '{channel_name}' for hash 0x{channel_hash:02x}")
            result = self._try_decrypt_with_key(packet, key, channel_name)
            if result:
                logger.debug(f"Successfully decrypted with '{channel_name}' key")
                return result
        else:
            logger.debug(f"No channel found for hash 0x{channel_hash:02x}")

        # Fallback: Try channel from topic
        key = self.channel_keys.get(channel_id)
        if key:
            logger.debug(f"Trying topic channel key '{channel_id}'")
            result = self._try_decrypt_with_key(packet, key, channel_id)
            if result:
                logger.debug(f"Successfully decrypted with topic channel '{channel_id}' key")
                return result

        # Last resort: Try all keys
        logger.debug(f"Hash/topic lookup failed, trying all {len(self.channel_keys)} available keys")
        for name, other_key in self.channel_keys.items():
            # Skip keys we already tried
            if channel_hash in self.channel_hash_to_key:
                tried_name, _ = self.channel_hash_to_key[channel_hash]
                if name == tried_name:
                    continue
            if name == channel_id:
                continue

            logger.debug(f"Trying alternate key '{name}'")
            result = self._try_decrypt_with_key(packet, other_key, name)
            if result:
                logger.info(f"Successfully decrypted with '{name}' key (hash was 0x{channel_hash:02x})")
                return result

        logger.debug(f"Failed to decrypt with any of {len(self.channel_keys)} available keys")
        return None

    def _try_decrypt_with_key(self, packet, key: bytes, key_name: str) -> Optional[mesh_pb2.Data]:
        """
        Try to decrypt packet with a specific key.

        Args:
            packet: MeshPacket protobuf with encrypted field
            key: PSK to try
            key_name: Name of the key (for debugging)

        Returns:
            Decrypted Data protobuf or None if decryption fails
        """
        key = self._normalize_key_length(key)
        encrypted_data = bytes(packet.encrypted)
        nonce = self._build_nonce(packet.id, getattr(packet, 'from'))

        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(nonce)), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

            logger.debug(f"Key '{key_name}': decrypted {len(decrypted)} bytes")

            data = mesh_pb2.Data()
            data.ParseFromString(decrypted)
            return data
        except Exception as e:
            logger.debug(f"Key '{key_name}' failed: {e}")
            return None

    @staticmethod
    def _normalize_key_length(key: bytes) -> bytes:
        """Normalize key to valid AES length (16 or 32 bytes)."""
        key_len = len(key)

        if key_len in (16, 32):
            return key
        if key_len < 16:
            return key + b'\x00' * (16 - key_len)
        if key_len < 32:
            return key + b'\x00' * (32 - key_len)
        return key[:32]

    @staticmethod
    def _build_nonce(packet_id: int, from_node: int) -> bytearray:
        """
        Build 16-byte nonce for AES-CTR encryption/decryption.

        Nonce structure: packet_id (8 bytes LE) + from_node (4 bytes LE) + zeros (4 bytes)
        """
        nonce = bytearray(16)
        nonce[0:8] = packet_id.to_bytes(8, byteorder='little')
        nonce[8:12] = from_node.to_bytes(4, byteorder='little')
        return nonce

    def encrypt_packet(self, data_payload: bytes, packet_id: int, from_node: int, channel_id: str) -> Optional[bytes]:
        """
        Encrypt a Data payload using AES-CTR for Meshtastic.

        Args:
            data_payload: Serialized mesh_pb2.Data protobuf to encrypt
            packet_id: Packet ID for nonce generation
            from_node: Source node ID for nonce generation
            channel_id: Channel ID to determine PSK

        Returns:
            Encrypted bytes or None if encryption fails
        """
        # Get the PSK for this channel
        key = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        if not key:
            logger.error(f"No PSK found for channel '{channel_id}'")
            return None

        key = self._normalize_key_length(key)
        nonce = self._build_nonce(packet_id, from_node)

        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(nonce)), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(data_payload) + encryptor.finalize()

            logger.debug(f"Encrypted {len(data_payload)} bytes with channel '{channel_id}' PSK")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None

    @staticmethod
    def _print_debug_info(packet, nonce: bytearray, key: bytes, encrypted_data: bytes):
        """Print debug information for decryption."""
        from_node = getattr(packet, 'from')
        print(f"Debug: packet_id={packet.id:#x}, from_node={from_node:#x}")
        print(f"Debug: nonce={nonce.hex()}")
        print(f"Debug: key={key.hex()}")
        print(f"Debug: encrypted_len={len(encrypted_data)}")
        print(f"Debug: encrypted_first_16={encrypted_data[:16].hex()}")

    def decrypt_openssl_salted(self, ciphertext_b64: str) -> Optional[str]:
        """Decrypt OpenSSL 'Salted__' Base64 using PBKDF2-HMAC-SHA256.

        Tries AES-256-CBC first, then AES-128-CBC. No MD5 fallback.
        """
        if not self.openssl_password:
            logger.debug("No OpenSSL password configured, skipping OpenSSL decryption")
            return None

        try:
            data = base64.b64decode(ciphertext_b64)
        except Exception as e:
            logger.debug(f"Base64 decode failed: {e}")
            return None

        return self._decrypt_openssl_common(data)

    # Note: raw Salted__ blobs are normalized to Base64 before decryption.

    def _decrypt_openssl_common(self, data: bytes) -> Optional[str]:
        """Common OpenSSL salted decryption with PBKDF2; tries AES-256 then AES-128."""
        try:
            if not data.startswith(b'Salted__'):
                logger.debug("Data does not have 'Salted__' header")
                return None

            if len(data) < 16 + 16:
                logger.debug("Data too short for Salted__ + salt + 1 block")
                return None

            salt = data[8:16]
            ciphertext = data[16:]

            if len(ciphertext) % 16 != 0:
                logger.debug("Ciphertext length is not a multiple of 16")
                return None

            # PBKDF2 key derivation (use configured iterations)
            key_iv = self._pbkdf2_derive(self.openssl_password.encode('utf-8'), salt, self.openssl_iterations)

            # Try AES-256-CBC first (32-byte key, 16-byte IV)
            result = self._try_aes_cbc_decrypt(ciphertext, key_iv[:32], key_iv[32:48])
            if result is not None:
                return result

            # Then try AES-128-CBC (use first 16 bytes as key, next 16 as IV)
            result = self._try_aes_cbc_decrypt(ciphertext, key_iv[:16], key_iv[32:48])
            return result
        except Exception as e:
            logger.debug(f"OpenSSL decrypt failed: {e}")
            return None

    def _pbkdf2_derive(self, password: bytes, salt: bytes, iterations: int) -> bytes:
        """Derive 48 bytes (32 key + 16 IV) via PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=int(iterations),
            backend=default_backend()
        )
        return kdf.derive(password)

    def _try_aes_cbc_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> Optional[str]:
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
            pad = plaintext_padded[-1]
            if pad == 0 or pad > 16:
                return None
            plaintext = plaintext_padded[:-pad]
            return plaintext.decode('utf-8', errors='replace')
        except Exception:
            return None

    def _derive_key_pbkdf2(self, salt: bytes) -> tuple[bytes, bytes]:
        """Derive key and IV using PBKDF2 (modern OpenSSL)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        key_iv = kdf.derive(self.openssl_password.encode('utf-8'))
        return key_iv[:32], key_iv[32:48]

    def _derive_key_md5(self, salt: bytes) -> tuple[bytes, bytes]:
        """Derive key and IV using MD5 (old OpenSSL)."""
        password = self.openssl_password.encode('utf-8')
        key_len, iv_len = 32, 16
        m = []
        i = 0

        while len(b''.join(m)) < (key_len + iv_len):
            md = hashlib.md5()
            data = password + salt
            if i > 0:
                data = m[i - 1] + data
            md.update(data)
            m.append(md.digest())
            i += 1

        ms = b''.join(m)
        return ms[:key_len], ms[key_len:key_len + iv_len]

    def encrypt_openssl_salted(self, plaintext: str, password: Optional[str] = None, *,
                               output: str = "base64", key_size: int = 256,
                               iterations: Optional[int] = None, salt: Optional[bytes] = None) -> str | bytes:
        """Encrypt text into OpenSSL 'Salted__' blob using PBKDF2-HMAC-SHA256.

        Args:
            plaintext: Text to encrypt
            password: Password to use (falls back to configured)
            output: 'base64' (default) or 'bytes'
            key_size: 256 or 128 for AES key size
            iterations: PBKDF2 iterations

        Returns:
            Base64 string if output='base64', otherwise raw bytes starting with b'Salted__'
        """
        pwd = password or self.openssl_password
        if not pwd:
            raise ValueError("OpenSSL password not provided for encryption")

        import os
        salt = salt or os.urandom(8)

        # Derive 48 bytes (32 key + 16 iv) via PBKDF2 with custom iterations
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=int(iterations or self.openssl_iterations),
            backend=default_backend()
        )
        key_iv = kdf.derive(pwd.encode('utf-8'))

        if key_size == 256:
            key = key_iv[:32]
            iv = key_iv[32:48]
        elif key_size == 128:
            key = key_iv[:16]
            iv = key_iv[32:48]
        else:
            raise ValueError("key_size must be 128 or 256")

        # PKCS7 padding
        data = plaintext.encode('utf-8')
        pad_len = 16 - (len(data) % 16)
        padded = data + bytes([pad_len]) * pad_len

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        blob = b"Salted__" + salt + ciphertext
        return base64.b64encode(blob).decode('ascii') if output == "base64" else blob
