"""
Utility functions for the Meshtastic MQTT package.
"""


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

    Args:
        node_id: Node ID as string (e.g., "@ffffffff", "3663383912", "+16504442323", "^all") or int

    Returns:
        Node ID as integer (uint32)

    Raises:
        ValueError: If node ID is invalid or out of range
    """
    if isinstance(node_id, int):
        node_num = node_id
    elif isinstance(node_id, str):
        # Validate max length (protobuf constraint: max 16 bytes)
        if len(node_id) > 16:
            raise ValueError(
                f"Node ID string too long: '{node_id}' ({len(node_id)} chars, max 16)"
            )

        if node_id.startswith('@') or node_id.startswith('!'):
            # Hex format with @ or ! prefix
            hex_part = node_id[1:]

            # Validate hex format (max 8 characters for 32-bit fixed32)
            if len(hex_part) > 8:
                raise ValueError(
                    f"Node ID hex value too long: '{node_id}' ({len(hex_part)} chars, max 8). "
                    f"Did you mean {node_id[0]}{hex_part[:8]}?"
                )

            if not hex_part:
                raise ValueError(f"Empty node ID after prefix: '{node_id}'")

            if not all(c in '0123456789abcdefABCDEF' for c in hex_part):
                raise ValueError(f"Invalid hex characters in node ID: '{node_id}'")

            node_num = int(hex_part, 16)
        elif node_id.startswith('^'):
            # Special IDs - convert to node numbers
            special_ids = {
                '^all': 0xFFFFFFFF,      # Broadcast to all nodes
                '^local': None,          # Local node (needs context)
            }

            lower_id = node_id.lower()
            if lower_id in special_ids:
                if lower_id == '^local':
                    raise ValueError(
                        "Node ID '^local' requires local node context. "
                        "Use your actual node ID (@12345678) or @ffffffff for broadcast."
                    )
                node_num = special_ids[lower_id]
            else:
                raise ValueError(
                    f"Unknown special node ID: '{node_id}'. "
                    f"Valid special IDs: ^all (broadcast)"
                )
        elif node_id.startswith('+'):
            # Phone number - these are string-only IDs, not convertible
            raise ValueError(
                f"Node ID '{node_id}' is a phone number format (string-only). "
                f"Use hex format (@12345678) or decimal for numeric operations."
            )
        else:
            # Decimal format
            try:
                node_num = int(node_id)
            except ValueError:
                raise ValueError(f"Invalid decimal node ID: '{node_id}'")
    else:
        raise ValueError(f"Invalid node_id type: {type(node_id).__name__}")

    # Validate uint32 range (protobuf fixed32: 0 to 0xFFFFFFFF)
    if node_num < 0 or node_num > 0xFFFFFFFF:
        raise ValueError(
            f"Node ID out of range: {node_num} "
            f"(valid range: 0 to 4294967295 / 0xFFFFFFFF)"
        )

    return node_num


def is_json_payload(payload: bytes) -> bool:
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
