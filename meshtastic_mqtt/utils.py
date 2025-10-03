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
    Parse node ID from string (decimal or hex with @) or int.

    Args:
        node_id: Node ID as string or int

    Returns:
        Node ID as integer
    """
    if isinstance(node_id, str):
        return int(node_id[1:], 16) if node_id.startswith('@') else int(node_id)
    return node_id


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
