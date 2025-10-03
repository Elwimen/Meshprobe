"""
xxd-style hex/ASCII dump utility.
"""


def hex_dump(data: bytes, width: int = 16, use_color: bool = True) -> str:
    """
    Create xxd-style hex/ASCII dump with optional colors.

    Args:
        data: Binary data to dump
        width: Number of bytes per line (default 16)
        use_color: Use ANSI colors for better readability

    Returns:
        Formatted hex dump string
    """
    # ANSI color codes
    GRAY = '\033[90m' if use_color else ''
    BOLD = '\033[1m' if use_color else ''
    BRIGHT_GREEN = '\033[92m' if use_color else ''
    BRIGHT_YELLOW = '\033[93m' if use_color else ''
    BRIGHT_CYAN = '\033[96m' if use_color else ''
    RESET = '\033[0m' if use_color else ''

    # Control characters (0x00-0x1F and 0x7F)
    CONTROL_CHARS = {
        0x00: 'NUL', 0x01: 'SOH', 0x02: 'STX', 0x03: 'ETX', 0x04: 'EOT', 0x05: 'ENQ', 0x06: 'ACK', 0x07: 'BEL',
        0x08: 'BS',  0x09: 'TAB', 0x0A: 'LF',  0x0B: 'VT',  0x0C: 'FF',  0x0D: 'CR',  0x0E: 'SO',  0x0F: 'SI',
        0x10: 'DLE', 0x11: 'DC1', 0x12: 'DC2', 0x13: 'DC3', 0x14: 'DC4', 0x15: 'NAK', 0x16: 'SYN', 0x17: 'ETB',
        0x18: 'CAN', 0x19: 'EM',  0x1A: 'SUB', 0x1B: 'ESC', 0x1C: 'FS',  0x1D: 'GS',  0x1E: 'RS',  0x1F: 'US',
        0x7F: 'DEL'
    }

    def get_color(byte_val):
        """Get color for a byte based on its ASCII representation."""
        if 32 <= byte_val < 127:
            char = chr(byte_val)
            return BOLD + BRIGHT_GREEN if char.isalnum() else BOLD + BRIGHT_YELLOW
        elif byte_val in CONTROL_CHARS:
            return BOLD + BRIGHT_CYAN
        return ''  # No color for other non-printable

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]

        # Hex representation (xxd style: grouped in pairs) with bold and color
        hex_pairs = []
        for j in range(0, len(chunk), 2):
            if j + 1 < len(chunk):
                color1 = get_color(chunk[j])
                color2 = get_color(chunk[j+1])
                # Color each hex digit pair
                pair = f'{color1}{chunk[j]:02x}{RESET if color1 else ""}{color2}{chunk[j+1]:02x}{RESET if color2 else ""}'
            else:
                color1 = get_color(chunk[j])
                pair = f'{color1}{chunk[j]:02x}{RESET if color1 else ""}'
            hex_pairs.append(pair)

        hex_part = ' '.join(hex_pairs)

        # ASCII representation with bold and color
        ascii_chars = []
        for b in chunk:
            if 32 <= b < 127:
                char = chr(b)
                # Alphanumeric: bold bright green
                if char.isalnum():
                    ascii_chars.append(f'{BOLD}{BRIGHT_GREEN}{char}{RESET}')
                # Special ASCII characters: bold bright yellow
                else:
                    ascii_chars.append(f'{BOLD}{BRIGHT_YELLOW}{char}{RESET}')
            else:
                # Non-printable: gray dot (not bold)
                ascii_chars.append(f'{GRAY}.{RESET}')
        ascii_part = ''.join(ascii_chars)

        # Calculate visible length of hex part (without ANSI codes)
        # Each full pair is 4 chars, single byte is 2 chars, + 1 space between pairs
        num_full_pairs = len(chunk) // 2
        has_odd_byte = len(chunk) % 2 == 1

        # Full pairs: 4 chars each, odd byte: 2 chars, spaces between all pairs
        visible_len = num_full_pairs * 4
        if has_odd_byte:
            visible_len += 2
        # Add spaces between pairs (total pairs - 1)
        num_total_pairs = num_full_pairs + (1 if has_odd_byte else 0)
        if num_total_pairs > 1:
            visible_len += num_total_pairs - 1

        # For full line: 39 chars for hex (8 pairs * 5 - 1)
        expected_hex_len = 39
        padding_needed = expected_hex_len - visible_len

        # Line with plain address, padding to align ASCII column
        lines.append(f'{i:08x}: {hex_part}{" " * padding_needed}  {ascii_part}')

    return '\n'.join(lines)
