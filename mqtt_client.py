#!/usr/bin/env python3
"""
Meshtastic MQTT Client CLI
Entry point for the refactored meshtastic_mqtt package.
"""

import sys
import argparse
import time

try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

from meshtastic_mqtt import MeshtasticMQTTClient
from meshtastic_mqtt.config import ServerConfig, NodeConfig, create_default_configs
from meshtastic_mqtt.logging_config import setup_logging


def filter_completer(prefix, parsed_args, **kwargs):
    """Custom completer for comma-separated filter types."""
    valid_types = ['text', 'position', 'nodeinfo', 'telemetry', 'routing', 'neighbor', 'map', 'encrypted', 'ascii']

    # If there's a comma, complete after the last comma
    if ',' in prefix:
        # Get already specified types
        parts = prefix.split(',')
        already_specified = [p.strip() for p in parts[:-1]]
        current = parts[-1]

        # Filter out already specified types
        available = [t for t in valid_types if t not in already_specified]

        # Return completions with the prefix preserved
        prefix_without_current = ','.join(parts[:-1]) + ','
        return [prefix_without_current + t for t in available if t.startswith(current)]
    else:
        # Complete the first type
        return [t for t in valid_types if t.startswith(prefix)]


def main():
    parser = argparse.ArgumentParser(description='Meshtastic MQTT Client')
    parser.add_argument('--server-config', default='server_config.json',
                       help='Path to server configuration file')
    parser.add_argument('--node-config', default='node_config.json',
                       help='Path to node configuration file')
    parser.add_argument('--root-topic', type=str,
                       help='Override MQTT root topic (e.g., msh, msh/EU_868/HR)')
    parser.add_argument('--create-configs', action='store_true',
                       help='Create default configuration files')
    parser.add_argument('--log-level', default='CRITICAL',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'NONE'],
                       help='Set logging level (NONE = disable logging)')
    parser.add_argument('--debug-modules', type=str,
                       help='Comma-separated list of modules to debug (e.g., client,parsers)')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    subparsers.add_parser('map', help='Publish position to mesh map')

    text_parser = subparsers.add_parser('text', help='Send text message to a node')
    text_parser.add_argument('to_node', help='Target node ID (decimal or hex with @ prefix, e.g., 3663383912 or @da548c90)')
    text_parser.add_argument('message', help='Message text')
    text_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    text_parser.add_argument('--hops', type=int, default=3, help='Hop limit')

    pos_parser = subparsers.add_parser('position', help='Send position to a node')
    pos_parser.add_argument('to_node', help='Target node ID (decimal or hex with @ prefix, e.g., 3663383912 or @da548c90)')
    pos_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    pos_parser.add_argument('--hops', type=int, default=3, help='Hop limit')

    listen_parser = subparsers.add_parser('listen', help='Listen for incoming messages on MQTT')
    listen_parser.add_argument('--duration', type=int, default=0, help='Duration in seconds (0 = forever)')
    listen_parser.add_argument('--openssl-password', type=str, help='Password to decrypt OpenSSL-encrypted messages')
    listen_parser.add_argument('--hex-dump', choices=['encrypted', 'decrypted', 'all'],
                               help='Show hex/ASCII dump: encrypted=failed decryption, decrypted=successfully decoded, all=both')
    filter_arg = listen_parser.add_argument('--filter', type=str,
                               help='Filter by message types (comma-separated): text,position,nodeinfo,telemetry,routing,neighbor,map,encrypted,ascii. Use / suffix to exclude: encrypted/')
    if ARGCOMPLETE_AVAILABLE:
        filter_arg.completer = filter_completer
    listen_parser.add_argument('--colored', action='store_true', help='Use colored output in hex dump')

    subparsers.add_parser('nodeinfo', help='Broadcast NODEINFO packet')
    subparsers.add_parser('telemetry', help='Broadcast device TELEMETRY packet')
    subparsers.add_parser('telemetry:env', help='Broadcast environment TELEMETRY packet')

    if ARGCOMPLETE_AVAILABLE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.create_configs:
        create_default_configs()
        return

    if not args.command:
        parser.print_help()
        return

    # Setup logging
    module_levels = {}
    if args.debug_modules:
        for module in args.debug_modules.split(','):
            module_levels[module.strip()] = 'DEBUG'

    # Use colored logging if --colored flag is present (for listen command)
    use_color_logging = args.colored if args.command == 'listen' and hasattr(args, 'colored') else False
    setup_logging(args.log_level, module_levels, use_color_logging)

    server_config = ServerConfig.from_json(args.server_config)
    node_config = NodeConfig.from_json(args.node_config)

    if args.root_topic:
        server_config.root_topic = args.root_topic
        print(f"Overriding root topic to: {args.root_topic}")

    openssl_password = args.openssl_password if args.command == 'listen' and hasattr(args, 'openssl_password') else None
    hex_dump_mode = args.hex_dump if args.command == 'listen' and hasattr(args, 'hex_dump') else None
    hex_dump_colored = args.colored if args.command == 'listen' and hasattr(args, 'colored') else False

    # Parse and validate filter types
    filter_types = None
    if args.command == 'listen' and hasattr(args, 'filter') and args.filter:
        valid_types = {'text', 'position', 'nodeinfo', 'telemetry', 'routing', 'neighbor', 'map', 'encrypted', 'ascii'}

        include_types = set()
        exclude_types = set()

        for t in args.filter.split(','):
            t = t.strip().lower()
            if t.endswith('/'):
                # Exclude type (negation)
                type_name = t[:-1]
                if type_name not in valid_types:
                    print(f"Error: Invalid filter type: {t}")
                    print(f"Valid types: {', '.join(sorted(valid_types))}")
                    sys.exit(1)
                exclude_types.add(type_name)
            else:
                # Include type
                if t not in valid_types:
                    print(f"Error: Invalid filter type: {t}")
                    print(f"Valid types: {', '.join(sorted(valid_types))}")
                    sys.exit(1)
                include_types.add(t)

        # Store as dict with include and exclude sets
        filter_types = {
            'include': include_types,
            'exclude': exclude_types
        }

    client = MeshtasticMQTTClient(server_config, node_config, openssl_password, hex_dump_mode, hex_dump_colored, filter_types)

    use_listener_id = (args.command == 'listen')
    subscribe = (args.command == 'listen')

    if not client.connect(use_listener_id=use_listener_id, subscribe=subscribe):
        print("Failed to connect to MQTT broker")
        sys.exit(1)

    try:
        if args.command == 'map':
            client.publish_map_position()
            time.sleep(1)
        elif args.command == 'text':
            client.send_text_message(args.message, args.to_node, args.channel, args.hops)
            time.sleep(1)
        elif args.command == 'position':
            client.send_position_message(args.to_node, args.channel, args.hops)
            time.sleep(1)
        elif args.command == 'nodeinfo':
            client.send_node_info()
            time.sleep(1)
        elif args.command == 'telemetry':
            client.send_telemetry()
            time.sleep(1)
        elif args.command == 'telemetry:env':
            client.send_environment()
            time.sleep(1)
        elif args.command == 'listen':
            print("Listening for messages...")
            print(f"Logging node data to: nodes/")
            if args.duration > 0:
                print(f"Will listen for {args.duration} seconds")
                time.sleep(args.duration)
            else:
                print("Press Ctrl+C to stop")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping...")
                    print(f"Node data saved to: nodes/")
                    client.print_stats()

    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
