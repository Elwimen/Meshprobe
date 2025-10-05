"""
Message filtering logic for Meshtastic MQTT client.
"""

from typing import Optional


class MessageFilter:
    """Handles message filtering based on type."""

    # Mapping from user-friendly filter names to portnum names
    PORTNUM_MAP = {
        'text': 'TEXT_MESSAGE_APP',
        'position': 'POSITION_APP',
        'nodeinfo': 'NODEINFO_APP',
        'telemetry': 'TELEMETRY_APP',
        'routing': 'ROUTING_APP',
        'neighbor': 'NEIGHBORINFO_APP',
        'map': 'MAP_REPORT_APP'
    }

    def __init__(self, filter_types: Optional[dict] = None):
        """
        Initialize MessageFilter.

        Args:
            filter_types: Dict with 'include' and 'exclude' sets (None = show all)
        """
        self.filter_types = filter_types

    def should_filter_encrypted(self) -> bool:
        """
        Check if encrypted messages should be filtered.

        Returns:
            True if encrypted messages should be filtered out
        """
        if not self.filter_types:
            return False

        include = self.filter_types.get('include', set())
        exclude = self.filter_types.get('exclude', set())

        if include and 'encrypted' not in include:
            return True
        if 'encrypted' in exclude:
            return True

        return False

    def should_filter_ascii(self) -> bool:
        """
        Check if ASCII messages should be filtered.

        Returns:
            True if ASCII messages should be filtered out
        """
        if not self.filter_types:
            return False

        include = self.filter_types.get('include', set())
        exclude = self.filter_types.get('exclude', set())

        if include and 'ascii' not in include:
            return True
        if 'ascii' in exclude:
            return True

        return False

    def should_filter_salted(self, is_salted: bool) -> bool:
        """Check if OpenSSL 'Salted__' text messages should be filtered."""
        if not is_salted or not self.filter_types:
            return False

        include = self.filter_types.get('include', set())
        exclude = self.filter_types.get('exclude', set())

        if include and 'salted' not in include:
            return True
        if 'salted' in exclude:
            return True

        return False

    @staticmethod
    def is_salted_ascii(payload: bytes, text: str) -> bool:
        """Detect SALTED in ASCII path: Base64 prefix or raw 'Salted__' header."""
        if not payload:
            return False
        try:
            if text.startswith('U2FsdGVk'):
                return True
        except Exception:
            pass
        return payload.startswith(b'Salted__')

    def should_filter_portnum(self, portnum_name: str) -> bool:
        """
        Check if a portnum should be filtered.

        Args:
            portnum_name: Portnum name (e.g., 'TEXT_MESSAGE_APP')

        Returns:
            True if this portnum should be filtered out
        """
        if not self.filter_types:
            return False

        include = self.filter_types.get('include', set())
        exclude = self.filter_types.get('exclude', set())

        # Check include filter
        if include:
            # Convert include types to portnum names (excluding special types)
            allowed_portnums = {
                self.PORTNUM_MAP.get(ft)
                for ft in include
                if ft not in ('encrypted', 'ascii') and ft in self.PORTNUM_MAP
            }
            return portnum_name not in allowed_portnums

        # Check exclude filter
        if exclude:
            # Convert exclude types to portnum names (excluding special types)
            excluded_portnums = {
                self.PORTNUM_MAP.get(ft)
                for ft in exclude
                if ft not in ('encrypted', 'ascii') and ft in self.PORTNUM_MAP
            }
            return portnum_name in excluded_portnums

        return False
