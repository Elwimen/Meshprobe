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
from meshtastic_mqtt.config import ServerConfig, NodeConfig, ClientConfig, create_default_configs
from meshtastic_mqtt.logging_config import setup_logging


def root_topic_completer(prefix, parsed_args, **kwargs):
    """Custom completer for --root-topic with region suggestions."""
    # All known Meshtastic regions
    regions = [
        'msh/US',           # United States
        'msh/EU_433',       # Europe 433MHz
        'msh/EU_868',       # Europe 868MHz
        'msh/UA_433',       # Ukraine 433MHz
        'msh/UA_868',       # Ukraine 868MHz
        'msh/CN',           # China
        'msh/JP',           # Japan
        'msh/KR',           # Korea
        'msh/TW',           # Taiwan
        'msh/IN',           # India
        'msh/TH',           # Thailand
        'msh/ANZ',          # Australia/New Zealand
        'msh/NZ_865',       # New Zealand 865MHz
        'msh/SG_923',       # Singapore
        'msh/MY_433',       # Malaysia 433MHz
        'msh/MY_919',       # Malaysia 919MHz
        'msh/PH_433',       # Philippines 433MHz
        'msh/PH_868',       # Philippines 868MHz
        'msh/PH_915',       # Philippines 915MHz
        'msh/RU',           # Russia
        'msh/LORA_24',      # 2.4GHz LoRa
        'msh',              # Root topic (all regions if allowed)
    ]
    return [r for r in regions if r.startswith(prefix)]


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
    parser.add_argument('--client-config', default='client_config.json',
                       help='Path to client configuration file')
    parser.add_argument('--server-config', default='server_config.json',
                       help='Path to server configuration file')
    parser.add_argument('--node-config', default='node_config.json',
                       help='Path to node configuration file')
    root_topic_arg = parser.add_argument('--root-topic', type=str,
                       help='Override MQTT root topic (e.g., msh/US, msh/EU_868)')
    if ARGCOMPLETE_AVAILABLE:
        root_topic_arg.completer = root_topic_completer
    parser.add_argument('--psk', type=str,
                       help='Override channel PSK (base64 encoded, e.g., AQ== or 1PG/OiApB1nwvP+rz05pAQ==)')
    parser.add_argument('--create-configs', action='store_true',
                       help='Create default configuration files')
    parser.add_argument('--log-level', default='CRITICAL',
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'NONE'],
                       help='Set logging level (NONE = disable logging)')
    parser.add_argument('--debug-modules', type=str,
                       help='Comma-separated list of modules to debug (e.g., client,parsers)')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    map_parser = subparsers.add_parser('map', help='Publish position to mesh map')
    map_parser.add_argument('--hex-dump', action='store_true',
                           help='Show hex/ASCII dump of transmitted packets')
    map_parser.add_argument('--colored', action='store_true',
                           help='Use colored output in hex dump')

    text_parser = subparsers.add_parser('text', help='Send text message to a node')
    text_parser.add_argument('to_node', help='Target node ID (decimal or hex with @ prefix, e.g., 3663383912 or @da548c90)')
    text_parser.add_argument('message', help='Message text')
    text_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    text_parser.add_argument('--hops', type=int, default=3, help='Hop limit')
    text_parser.add_argument('--openssl-password', type=str,
                            help='Encrypt text with OpenSSL salted format (AES-256-CBC) using this password')
    text_parser.add_argument('--base64', action='store_true',
                            help='When encrypting, send Base64 (U2FsdGVk...) instead of raw Salted__ bytes')
    text_parser.add_argument('--pbkdf2-iter', type=int,
                            help='PBKDF2-HMAC-SHA256 iteration count for SALTED encryption (default 10000)')
    text_parser.add_argument('--openssl-fixed-salt', type=str,
                            help='TEST ONLY: 16 hex chars (8 bytes) to fix OpenSSL salt')
    text_parser.add_argument('--hex-dump', action='store_true',
                            help='Show hex/ASCII dump of transmitted packets')
    text_parser.add_argument('--colored', action='store_true',
                            help='Use colored output in hex dump')

    pos_parser = subparsers.add_parser('position', help='Send position to a node')
    pos_parser.add_argument('to_node', help='Target node ID (decimal or hex with @ prefix, e.g., 3663383912 or @da548c90)')
    pos_parser.add_argument('--channel', type=int, default=0, help='Channel index')
    pos_parser.add_argument('--hops', type=int, default=3, help='Hop limit')
    pos_parser.add_argument('--randomize', action='store_true',
                           help='Randomize position with Gaussian noise (±0.025°, similar to map command)')
    pos_parser.add_argument('--hex-dump', action='store_true',
                           help='Show hex/ASCII dump of transmitted packets')
    pos_parser.add_argument('--colored', action='store_true',
                           help='Use colored output in hex dump')

    listen_parser = subparsers.add_parser('listen', help='Listen for incoming messages on MQTT')
    listen_parser.add_argument('--duration', type=int, default=0, help='Duration in seconds (0 = forever)')
    listen_parser.add_argument('--openssl-password', type=str, help='Password to decrypt OpenSSL-encrypted messages')
    listen_parser.add_argument('--hex-dump', choices=['full', 'payload', 'encrypted', 'decrypted', 'raw'],
                               help='Show hex/ASCII dump: full=ServiceEnvelope packet, payload=encrypted+decrypted data, encrypted=failed decryption only, decrypted=successfully decoded only, raw=raw MQTT bytes')
    listen_parser.add_argument('--pbkdf2-iter', type=int,
                               help='PBKDF2-HMAC-SHA256 iteration count for SALTED decryption (default 10000)')
    filter_arg = listen_parser.add_argument('--filter', type=str,
                               help='Show only these message types (comma-separated): text,position,nodeinfo,telemetry,routing,neighbor,map,encrypted,ascii')
    if ARGCOMPLETE_AVAILABLE:
        filter_arg.completer = filter_completer
    filter_out_arg = listen_parser.add_argument('--filter-out', type=str,
                               help='Hide these message types (comma-separated): text,position,nodeinfo,telemetry,routing,neighbor,map,encrypted,ascii')
    if ARGCOMPLETE_AVAILABLE:
        filter_out_arg.completer = filter_completer
    listen_parser.add_argument('--colored', action='store_true', help='Use colored output in hex dump')

    nodeinfo_parser = subparsers.add_parser('nodeinfo', help='Broadcast NODEINFO packet')
    nodeinfo_parser.add_argument('--hex-dump', action='store_true',
                                help='Show hex/ASCII dump of transmitted packets')
    nodeinfo_parser.add_argument('--colored', action='store_true',
                                help='Use colored output in hex dump')

    telemetry_parser = subparsers.add_parser('telemetry', help='Broadcast device TELEMETRY packet')
    telemetry_parser.add_argument('--hex-dump', action='store_true',
                                 help='Show hex/ASCII dump of transmitted packets')
    telemetry_parser.add_argument('--colored', action='store_true',
                                 help='Use colored output in hex dump')

    telemetry_env_parser = subparsers.add_parser('telemetry:env', help='Broadcast environment TELEMETRY packet')
    telemetry_env_parser.add_argument('--hex-dump', action='store_true',
                                     help='Show hex/ASCII dump of transmitted packets')
    telemetry_env_parser.add_argument('--colored', action='store_true',
                                     help='Use colored output in hex dump')

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

    # Use colored logging if --colored flag is present
    use_color_logging = args.colored if hasattr(args, 'colored') and args.colored else False
    setup_logging(args.log_level, module_levels, use_color_logging)

    client_config = ClientConfig.from_json(args.client_config)
    server_config = ServerConfig.from_json(args.server_config)
    node_config = NodeConfig.from_json(args.node_config)

    if args.root_topic:
        server_config.root_topic = args.root_topic
        print(f"Overriding root topic to: {args.root_topic}")

    # Override PSK if provided via command line
    if hasattr(args, 'psk') and args.psk:
        import base64
        try:
            psk_bytes = base64.b64decode(args.psk)
            # Override all channels with this PSK
            for channel_name in node_config.channels:
                node_config.channels[channel_name]['psk'] = args.psk
            print(f"Overriding PSK for all channels ({len(psk_bytes)} bytes)")
        except Exception as e:
            print(f"Error: Invalid PSK base64: {e}")
            sys.exit(1)

    openssl_password = None
    if hasattr(args, 'openssl_password'):
        # For listen: decrypt salted messages; for text: encrypt if provided
        openssl_password = args.openssl_password

    # Handle hex_dump for both RX (listen) and TX (send commands)
    # For listen: hex_dump is a choice ('full', 'payload', 'encrypted', 'decrypted')
    # For send commands: hex_dump is a boolean (True shows full packet)
    hex_dump_mode = None
    if hasattr(args, 'hex_dump') and args.hex_dump:
        hex_dump_mode = args.hex_dump

    # Handle colored flag for both listen and send commands
    hex_dump_colored = args.colored if hasattr(args, 'colored') and args.colored else False

    # Parse and validate filter types
    filter_types = None
    if args.command == 'listen':
        valid_types = {'text', 'position', 'nodeinfo', 'telemetry', 'routing', 'neighbor', 'map', 'encrypted', 'ascii', 'salted'}

        include_types = set()
        exclude_types = set()

        # Parse --filter
        if hasattr(args, 'filter') and args.filter:
            for t in args.filter.split(','):
                t = t.strip().lower()
                if t not in valid_types:
                    print(f"Error: Invalid filter type: {t}")
                    print(f"Valid types: {', '.join(sorted(valid_types))}")
                    sys.exit(1)
                include_types.add(t)

        # Parse --filter-out
        if hasattr(args, 'filter_out') and args.filter_out:
            for t in args.filter_out.split(','):
                t = t.strip().lower()
                if t not in valid_types:
                    print(f"Error: Invalid filter-out type: {t}")
                    print(f"Valid types: {', '.join(sorted(valid_types))}")
                    sys.exit(1)
                exclude_types.add(t)

        # If both --filter and --filter-out are used, remove excluded types from include
        if include_types and exclude_types:
            include_types -= exclude_types
            exclude_types.clear()  # Only use include logic when both are specified

        # Store as dict with include and exclude sets
        if include_types or exclude_types:
            filter_types = {
                'include': include_types,
                'exclude': exclude_types
            }

    # Store runtime options in client_config for publisher/crypto
    if args.command == 'text':
        setattr(client_config, 'openssl_send_base64', bool(getattr(args, 'base64', False)))
        if getattr(args, 'pbkdf2_iter', None) is not None:
            setattr(client_config, 'openssl_pbkdf2_iter', int(args.pbkdf2_iter))
        if getattr(args, 'openssl_fixed_salt', None):
            fs = args.openssl_fixed_salt.strip()
            if len(fs) != 16:
                print('Error: --openssl-fixed-salt must be exactly 16 hex characters (8 bytes)')
                sys.exit(1)
            try:
                # Validate hex; store as lowercase hex string
                bytes.fromhex(fs)
            except ValueError:
                print('Error: --openssl-fixed-salt must be valid hex (0-9a-f)')
                sys.exit(1)
            setattr(client_config, 'openssl_fixed_salt', fs.lower())
    elif args.command == 'listen':
        if getattr(args, 'pbkdf2_iter', None) is not None:
            setattr(client_config, 'openssl_pbkdf2_iter', int(args.pbkdf2_iter))

    client = MeshtasticMQTTClient(server_config, node_config, client_config, openssl_password, hex_dump_mode, hex_dump_colored, filter_types)

    use_listener_id = (args.command == 'listen')
    subscribe = (args.command == 'listen')

    try:
        if not client.connect(use_listener_id=use_listener_id, subscribe=subscribe):
            print("Failed to connect to MQTT broker")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nConnection cancelled by user")
        sys.exit(0)

    try:
        if args.command == 'map':
            client.publish_map_position()
            time.sleep(1)
        elif args.command == 'text':
            # openssl_password already attached to client/publisher in connect()
            client.send_text_message(args.message, args.to_node, args.channel, args.hops)
            time.sleep(1)
        elif args.command == 'position':
            randomize = args.randomize if hasattr(args, 'randomize') else False
            client.send_position_message(args.to_node, args.channel, args.hops, randomize)
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
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(0)
