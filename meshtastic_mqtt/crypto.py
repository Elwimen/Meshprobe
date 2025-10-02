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

        Args:
            channels: Dictionary of channel configurations

        Returns:
            Dictionary mapping channel names to PSK bytes
        """
        if not channels:
            return {"default": CryptoEngine.DEFAULT_PSK}

        keys = {}
        for channel_name, channel_config in channels.items():
            psk_b64 = channel_config.get('psk')
            if psk_b64:
                keys[channel_name] = base64.b64decode(psk_b64)
            else:
                keys[channel_name] = CryptoEngine.DEFAULT_PSK

        return keys

    def decrypt_packet(self, packet, channel_id: str, debug: bool = False) -> Optional[mesh_pb2.Data]:
        """
        Decrypt an encrypted Meshtastic packet using AES-CTR.

        Args:
            packet: MeshPacket protobuf with encrypted field
            channel_id: Channel ID to determine PSK
            debug: Enable debug output

        Returns:
            Decrypted Data protobuf or None if decryption fails
        """
        if not packet.HasField('encrypted'):
            return None

        key = self.channel_keys.get(channel_id) or self.channel_keys.get('default')
        if not key:
            return None

        key = self._normalize_key_length(key)
        encrypted_data = bytes(packet.encrypted)
        nonce = self._build_nonce(packet.id, getattr(packet, 'from'))

        if debug:
            self._print_debug_info(packet, nonce, key, encrypted_data)

        cipher = Cipher(algorithms.AES(key), modes.CTR(bytes(nonce)), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()

        if debug:
            print(f"Debug: decrypted_len={len(decrypted)}")
            print(f"Debug: decrypted_first_32={decrypted[:min(32, len(decrypted))].hex()}")

        try:
            data = mesh_pb2.Data()
            data.ParseFromString(decrypted)
            return data
        except Exception as e:
            if debug:
                print(f"Failed to parse decrypted data: {e}")
                print(f"Full decrypted hex: {decrypted.hex()}")
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
            return None

        try:
            data = base64.b64decode(ciphertext_b64)

            if not data.startswith(b'Salted__'):
                return None

            salt = data[8:16]
            ciphertext = data[16:]

            try:
                key, iv = self._derive_key_pbkdf2(salt)
            except Exception:
                key, iv = self._derive_key_md5(salt)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

            padding_len = plaintext_padded[-1]
            plaintext = plaintext_padded[:-padding_len]

            return plaintext.decode('utf-8', errors='replace')
        except Exception as e:
            print(f"   [OpenSSL decrypt failed: {e}]")
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
