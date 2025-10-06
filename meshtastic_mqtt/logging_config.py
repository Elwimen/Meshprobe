"""
Logging configuration for meshtastic_mqtt package.
"""

import logging
import sys
from typing import Optional


class LoggingManager:
    """Manager for logging configuration."""

    class ColoredFormatter(logging.Formatter):
        """Colored log formatter for console output."""

        COLORS = {
            'DEBUG': '\033[36m',     # Cyan
            'INFO': '\033[32m',      # Green
            'WARNING': '\033[33m',   # Yellow
            'ERROR': '\033[31m',     # Red
            'CRITICAL': '\033[35m',  # Magenta
        }
        RESET = '\033[0m'

        def __init__(self, fmt=None, use_color=True):
            super().__init__(fmt)
            self.use_color = use_color

        def format(self, record):
            if self.use_color and record.levelname in self.COLORS:
                record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            return super().format(record)

    @classmethod
    def setup(cls, level: str = 'WARNING', module_levels: Optional[dict] = None, use_color: bool = True):
        """
        Setup logging configuration.

        Args:
            level: Default log level (DEBUG, INFO, WARNING, ERROR, CRITICAL, NONE)
            module_levels: Dict of module-specific levels, e.g. {'client': 'DEBUG', 'parsers': 'INFO'}
            use_color: Use colored output for log messages
        """
        # Handle NONE - disable all logging
        if level.upper() == 'NONE':
            root_logger = logging.getLogger('meshtastic_mqtt')
            root_logger.setLevel(logging.CRITICAL + 1)  # Higher than any level
            return

        log_level = getattr(logging, level.upper(), logging.WARNING)

        handler = logging.StreamHandler(sys.stderr)
        formatter = cls.ColoredFormatter(
            '%(levelname)s [%(name)s] %(message)s',
            use_color=use_color
        )
        handler.setFormatter(formatter)

        root_logger = logging.getLogger('meshtastic_mqtt')
        root_logger.setLevel(log_level)
        root_logger.addHandler(handler)

        if module_levels:
            for module, mod_level in module_levels.items():
                logger = logging.getLogger(f'meshtastic_mqtt.{module}')
                logger.setLevel(getattr(logging, mod_level.upper(), logging.WARNING))

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """
        Get logger for a module.

        Args:
            name: Module name (e.g., 'client', 'parsers')

        Returns:
            Logger instance
        """
        return logging.getLogger(f'meshtastic_mqtt.{name}')


# Backward compatibility functions
def setup_logging(level: str = 'WARNING', module_levels: Optional[dict] = None, use_color: bool = True):
    """
    Setup logging configuration.

    This is a backward compatibility wrapper around LoggingManager.setup().

    Args:
        level: Default log level (DEBUG, INFO, WARNING, ERROR, CRITICAL, NONE)
        module_levels: Dict of module-specific levels, e.g. {'client': 'DEBUG', 'parsers': 'INFO'}
        use_color: Use colored output for log messages
    """
    LoggingManager.setup(level, module_levels, use_color)


def get_logger(name: str) -> logging.Logger:
    """
    Get logger for a module.

    This is a backward compatibility wrapper around LoggingManager.get_logger().

    Args:
        name: Module name (e.g., 'client', 'parsers')

    Returns:
        Logger instance
    """
    return LoggingManager.get_logger(name)
