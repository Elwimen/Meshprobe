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

    def __init__(self, channel_keys: dict[str, bytes], openssl_password: Optional[str] = None):
        """
        Initialize CryptoEngine.

        Args:
            channel_keys: Dictionary mapping channel names to PSK bytes
            openssl_password: Optional password for OpenSSL-encrypted messages
        """
        self.channel_keys = channel_keys if channel_keys else {"default": self.DEFAULT_PSK}
        self.openssl_password = openssl_password

    @staticmethod
    def calculate_channel_hash(psk: bytes) -> int:
        """Calculate channel hash from PSK (first byte of SHA256)."""
        return hashlib.sha256(psk).digest()[0]

    @staticmethod
    def load_channel_keys(channels: dict) -> dict[str, bytes]:
        """
        Load channel PSKs from configuration.
        Supports both formats:
        - Old: {"LongFast": {"psk": "AQ=="}}
        - New: {"0": {"name": "LongFast", "psk": "AQ=="}}

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

            # New format with index: {"0": {"name": "LongFast", "psk": "..."}}
            if key.isdigit() and 'name' in channel_config:
                channel_name = channel_config['name']
                keys[channel_name] = base64.b64decode(psk_b64)
                logger.debug(f"Loaded channel {key} -> '{channel_name}'")
            # Old format: {"LongFast": {"psk": "..."}}
            else:
                keys[key] = base64.b64decode(psk_b64)
                logger.debug(f"Loaded channel '{key}'")

        if not keys:
            keys["default"] = CryptoEngine.DEFAULT_PSK

        return keys

    def decrypt_packet(self, packet, channel_id: str, debug: bool = False) -> Optional[mesh_pb2.Data]:
        """
        Decrypt an encrypted Meshtastic packet using AES-CTR.
        Tries the specified channel key first, then all other keys if that fails.

        Args:
            packet: MeshPacket protobuf with encrypted field
            channel_id: Channel ID to determine PSK
            debug: Enable debug output (deprecated, use logging instead)

        Returns:
            Decrypted Data protobuf or None if decryption fails
        """
        if not packet.HasField('encrypted'):
            return None

        logger.debug(f"Attempting to decrypt packet for channel '{channel_id}'")

        # Try specified channel key first
        key = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        if key:
            logger.debug(f"Trying primary key for channel '{channel_id}'")
            result = self._try_decrypt_with_key(packet, key, channel_id)
            if result:
                logger.debug(f"Successfully decrypted with channel '{channel_id}' key")
                return result

        # Try all other keys
        logger.debug(f"Primary key failed, trying all {len(self.channel_keys)} available keys")
        for name, other_key in self.channel_keys.items():
            if name == channel_id or (channel_id not in self.channel_keys and name == 'default'):
                continue  # Already tried this key

            logger.debug(f"Trying alternate key '{name}'")
            result = self._try_decrypt_with_key(packet, other_key, name)
            if result:
                logger.info(f"Successfully decrypted with '{name}' key (expected '{channel_id}')")
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
        Build 16-byte nonce for AES-CTR decryption.

        Nonce structure: packet_id (8 bytes LE) + from_node (4 bytes LE) + zeros (4 bytes)
        """
        nonce = bytearray(16)
        nonce[0:8] = packet_id.to_bytes(8, byteorder='little')
        nonce[8:12] = from_node.to_bytes(4, byteorder='little')
        return nonce

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
        """
        Decrypt OpenSSL 'Salted__' format (AES-256-CBC with password).

        Args:
            ciphertext_b64: Base64-encoded ciphertext

        Returns:
            Decrypted plaintext or None if decryption fails
        """
        if not self.openssl_password:
            logger.debug("No OpenSSL password configured, skipping OpenSSL decryption")
            return None

        try:
            logger.debug("Attempting OpenSSL decryption")
            data = base64.b64decode(ciphertext_b64)

            if not data.startswith(b'Salted__'):
                logger.debug("Data does not have 'Salted__' header")
                return None

            salt = data[8:16]
            ciphertext = data[16:]

            try:
                key, iv = self._derive_key_pbkdf2(salt)
                logger.debug("Using PBKDF2 key derivation")
            except Exception:
                key, iv = self._derive_key_md5(salt)
                logger.debug("Using MD5 key derivation")

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

            padding_len = plaintext_padded[-1]
            plaintext = plaintext_padded[:-padding_len]

            result = plaintext.decode('utf-8', errors='replace')
            logger.debug(f"OpenSSL decryption successful, {len(result)} chars")
            return result
        except Exception as e:
            logger.debug(f"OpenSSL decrypt failed: {e}")
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
