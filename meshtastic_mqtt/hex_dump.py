"""
xxd-style hex/ASCII dump utility.
"""


class HexDumper:
    """xxd-style hex/ASCII dumper with optional colors."""

    # ANSI color codes
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_CYAN = '\033[96m'
    RESET = '\033[0m'

    # Control characters (0x00-0x1F and 0x7F)
    CONTROL_CHARS = {
        0x00: 'NUL', 0x01: 'SOH', 0x02: 'STX', 0x03: 'ETX', 0x04: 'EOT', 0x05: 'ENQ', 0x06: 'ACK', 0x07: 'BEL',
        0x08: 'BS',  0x09: 'TAB', 0x0A: 'LF',  0x0B: 'VT',  0x0C: 'FF',  0x0D: 'CR',  0x0E: 'SO',  0x0F: 'SI',
        0x10: 'DLE', 0x11: 'DC1', 0x12: 'DC2', 0x13: 'DC3', 0x14: 'DC4', 0x15: 'NAK', 0x16: 'SYN', 0x17: 'ETB',
        0x18: 'CAN', 0x19: 'EM',  0x1A: 'SUB', 0x1B: 'ESC', 0x1C: 'FS',  0x1D: 'GS',  0x1E: 'RS',  0x1F: 'US',
        0x7F: 'DEL'
    }

    def __init__(self, width: int = 16, use_color: bool = True):
        """
        Initialize HexDumper.

        Args:
            width: Number of bytes per line (default 16)
            use_color: Use ANSI colors for better readability
        """
        self.width = width
        self.use_color = use_color

    def dump(self, data: bytes) -> str:
        """
        Create xxd-style hex/ASCII dump with optional colors.

        Args:
            data: Binary data to dump

        Returns:
            Formatted hex dump string
        """
        lines = []
        for i in range(0, len(data), self.width):
            chunk = data[i:i+self.width]
            hex_part = self._format_hex_pairs(chunk)
            ascii_part = self._format_ascii(chunk)

            # Calculate padding needed for alignment
            visible_len = self._calculate_visible_length(chunk)
            expected_hex_len = 39  # For full 16-byte line
            padding_needed = expected_hex_len - visible_len

            lines.append(f'{i:08x}: {hex_part}{" " * padding_needed}  {ascii_part}')

        return '\n'.join(lines)

    def _get_color(self, byte_val: int) -> str:
        """Get color for a byte based on its ASCII representation."""
        if not self.use_color:
            return ''

        if 32 <= byte_val < 127:
            char = chr(byte_val)
            return (self.BOLD + self.BRIGHT_GREEN) if char.isalnum() else (self.BOLD + self.BRIGHT_YELLOW)
        elif byte_val in self.CONTROL_CHARS:
            return self.BOLD + self.BRIGHT_CYAN

        return ''

    def _format_hex_pairs(self, chunk: bytes) -> str:
        """Format hex representation (xxd style: grouped in pairs) with color."""
        hex_pairs = []
        for j in range(0, len(chunk), 2):
            if j + 1 < len(chunk):
                color1 = self._get_color(chunk[j])
                color2 = self._get_color(chunk[j+1])
                reset1 = self.RESET if (color1 and self.use_color) else ""
                reset2 = self.RESET if (color2 and self.use_color) else ""
                pair = f'{color1}{chunk[j]:02x}{reset1}{color2}{chunk[j+1]:02x}{reset2}'
            else:
                color1 = self._get_color(chunk[j])
                reset1 = self.RESET if (color1 and self.use_color) else ""
                pair = f'{color1}{chunk[j]:02x}{reset1}'
            hex_pairs.append(pair)

        return ' '.join(hex_pairs)

    def _format_ascii(self, chunk: bytes) -> str:
        """Format ASCII representation with color."""
        ascii_chars = []
        for b in chunk:
            if 32 <= b < 127:
                char = chr(b)
                if char.isalnum():
                    colored = f'{self.BOLD}{self.BRIGHT_GREEN}{char}{self.RESET}' if self.use_color else char
                else:
                    colored = f'{self.BOLD}{self.BRIGHT_YELLOW}{char}{self.RESET}' if self.use_color else char
                ascii_chars.append(colored)
            else:
                dot = f'{self.GRAY}.{self.RESET}' if self.use_color else '.'
                ascii_chars.append(dot)

        return ''.join(ascii_chars)

    def _calculate_visible_length(self, chunk: bytes) -> int:
        """Calculate visible length of hex part (without ANSI codes)."""
        num_full_pairs = len(chunk) // 2
        has_odd_byte = len(chunk) % 2 == 1

        visible_len = num_full_pairs * 4
        if has_odd_byte:
            visible_len += 2

        num_total_pairs = num_full_pairs + (1 if has_odd_byte else 0)
        if num_total_pairs > 1:
            visible_len += num_total_pairs - 1

        return visible_len


# Backward compatibility function
def hex_dump(data: bytes, width: int = 16, use_color: bool = True) -> str:
    """
    Create xxd-style hex/ASCII dump with optional colors.

    This is a backward compatibility wrapper around HexDumper.dump().

    Args:
        data: Binary data to dump
        width: Number of bytes per line (default 16)
        use_color: Use ANSI colors for better readability

    Returns:
        Formatted hex dump string
    """
    dumper = HexDumper(width=width, use_color=use_color)
    return dumper.dump(data)
