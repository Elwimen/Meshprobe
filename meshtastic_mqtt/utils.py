"""
Utility functions for the Meshtastic MQTT package.
"""

from .exceptions import NodeIdError


class NodeIdParser:
    """Parser for Meshtastic node IDs with validation."""

    MAX_STRING_LENGTH = 16
    MAX_HEX_LENGTH = 8
    UINT32_MAX = 0xFFFFFFFF

    SPECIAL_IDS = {
        '^all': 0xFFFFFFFF,      # Broadcast to all nodes
        '^local': None,          # Local node (needs context)
    }

    @classmethod
    def parse(cls, node_id: str | int) -> int:
        """
        Parse and validate node ID from string (decimal or hex with @/!) or int.

        Args:
            node_id: Node ID as string (e.g., "@ffffffff", "3663383912", "^all") or int

        Returns:
            Node ID as integer (uint32)

        Raises:
            NodeIdError: If node ID is invalid or out of range
        """
        if isinstance(node_id, int):
            return cls._validate_range(node_id)

        if not isinstance(node_id, str):
            raise NodeIdError(f"Invalid node_id type: {type(node_id).__name__}")

        cls._validate_length(node_id)

        if node_id.startswith('@') or node_id.startswith('!'):
            return cls._parse_hex(node_id)
        elif node_id.startswith('^'):
            return cls._parse_special(node_id)
        elif node_id.startswith('+'):
            raise NodeIdError(
                f"Node ID '{node_id}' is a phone number format (string-only). "
                f"Use hex format (@12345678) or decimal for numeric operations."
            )
        else:
            return cls._parse_decimal(node_id)

    @classmethod
    def _validate_length(cls, node_id: str) -> None:
        """Validate node ID string length."""
        if len(node_id) > cls.MAX_STRING_LENGTH:
            raise NodeIdError(
                f"Node ID string too long: '{node_id}' ({len(node_id)} chars, max {cls.MAX_STRING_LENGTH})"
            )

    @classmethod
    def _parse_hex(cls, node_id: str) -> int:
        """Parse hex format node ID (@ffffffff or !12345678)."""
        hex_part = node_id[1:]

        if len(hex_part) > cls.MAX_HEX_LENGTH:
            raise NodeIdError(
                f"Node ID hex value too long: '{node_id}' ({len(hex_part)} chars, max {cls.MAX_HEX_LENGTH}). "
                f"Did you mean {node_id[0]}{hex_part[:cls.MAX_HEX_LENGTH]}?"
            )

        if not hex_part:
            raise NodeIdError(f"Empty node ID after prefix: '{node_id}'")

        if not all(c in '0123456789abcdefABCDEF' for c in hex_part):
            raise NodeIdError(f"Invalid hex characters in node ID: '{node_id}'")

        return cls._validate_range(int(hex_part, 16))

    @classmethod
    def _parse_special(cls, node_id: str) -> int:
        """Parse special node IDs (^all, ^local)."""
        lower_id = node_id.lower()

        if lower_id not in cls.SPECIAL_IDS:
            valid = ', '.join(cls.SPECIAL_IDS.keys())
            raise NodeIdError(
                f"Unknown special node ID: '{node_id}'. "
                f"Valid special IDs: {valid}"
            )

        if lower_id == '^local':
            raise NodeIdError(
                "Node ID '^local' requires local node context. "
                "Use your actual node ID (@12345678) or @ffffffff for broadcast."
            )

        return cls.SPECIAL_IDS[lower_id]

    @classmethod
    def _parse_decimal(cls, node_id: str) -> int:
        """Parse decimal format node ID."""
        try:
            return cls._validate_range(int(node_id))
        except ValueError as e:
            raise NodeIdError(f"Invalid decimal node ID: '{node_id}'") from e

    @classmethod
    def _validate_range(cls, node_num: int) -> int:
        """Validate node ID is within uint32 range."""
        if node_num < 0 or node_num > cls.UINT32_MAX:
            raise NodeIdError(
                f"Node ID out of range: {node_num} "
                f"(valid range: 0 to 4294967295 / 0xFFFFFFFF)"
            )
        return node_num


class PayloadDetector:
    """Detector for different payload types."""

    @staticmethod
    def is_json(payload: bytes) -> bool:
        """
        Check if payload is JSON by examining first non-whitespace character.

        Args:
            payload: Bytes to check

        Returns:
            True if payload appears to be JSON
        """
        if not payload:
            return False

        # Skip leading whitespace
        for byte in payload:
            if byte in (0x20, 0x09, 0x0A, 0x0D):  # space, tab, LF, CR
                continue
            # JSON must start with { or [
            return byte in (0x7B, 0x5B)  # { or [

        return False

    @staticmethod
    def is_ascii_text(payload: bytes) -> bool:
        """
        Check if payload is plain ASCII text.

        Args:
            payload: Bytes to check

        Returns:
            True if all bytes are printable ASCII or whitespace
        """
        if not payload or len(payload) > 1024:  # Skip large payloads
            return False

        # Check if all bytes are printable ASCII or whitespace
        for byte in payload:
            if not (0x20 <= byte <= 0x7E or byte in (0x09, 0x0A, 0x0D)):
                return False

        return True


# Backward compatibility functions
def format_node_id_hex(node_id: int) -> str:
    """
    Format node ID as hex string with ! prefix.

    Args:
        node_id: Node ID as integer

    Returns:
        Formatted string like "!12345678"
    """
    return f"!{node_id:08x}"


def parse_node_id(node_id: str | int) -> int:
    """
    Parse and validate node ID from string (decimal or hex with @/!) or int.

    This is a backward compatibility wrapper around NodeIdParser.parse().

    Args:
        node_id: Node ID as string (e.g., "@ffffffff", "3663383912", "^all") or int

    Returns:
        Node ID as integer (uint32)

    Raises:
        ValueError: If node ID is invalid or out of range (for backward compatibility)
    """
    try:
        return NodeIdParser.parse(node_id)
    except NodeIdError as e:
        # Convert to ValueError for backward compatibility
        raise ValueError(str(e)) from e


def is_json_payload(payload: bytes) -> bool:
    """
    Check if payload is JSON by examining first non-whitespace character.

    This is a backward compatibility wrapper around PayloadDetector.is_json().

    Args:
        payload: Bytes to check

    Returns:
        True if payload appears to be JSON
    """
    return PayloadDetector.is_json(payload)


def is_ascii_text(payload: bytes) -> bool:
    """
    Check if payload is plain ASCII text.

    This is a backward compatibility wrapper around PayloadDetector.is_ascii_text().

    Args:
        payload: Bytes to check

    Returns:
        True if all bytes are printable ASCII or whitespace
    """
    return PayloadDetector.is_ascii_text(payload)
