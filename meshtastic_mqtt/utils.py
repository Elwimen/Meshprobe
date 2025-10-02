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
