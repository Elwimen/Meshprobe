# Meshprobe

CLI toolkit for probing, inspecting, and interacting with Meshtastic networks over MQTT.

## Features

- Listen to and decode Meshtastic MQTT traffic with hex dumps
- Send text messages, positions, node info, and telemetry
- Publish to map reporting topics
- Decrypt packets with channel PSK or OpenSSL encryption
- Filter and analyze specific packet types
- Track and log node database locally

## Requirements

- Python 3.10+
- Packages: `paho-mqtt`, `meshtastic` (protobufs)
- Optional: `argcomplete` (for tab completion)

## Installation

```bash
pip install paho-mqtt meshtastic argcomplete
```

## Quick Start

1. Create default configs:
   ```bash
   python3 meshprobe.py --create-configs
   # Or run as module:
   python3 -m meshprobe --create-configs
   ```
   This creates `server_config.json`, `node_config.json`, and `client_config.json`.

2. Edit `node_config.json` and set a valid node ID (e.g., `"!da548c90"`). Optionally configure channel PSKs.

3. Listen to messages:
   ```bash
   python3 meshprobe.py listen --duration 60
   # Or run as module:
   python3 -m meshprobe listen --duration 60
   ```

## Usage

Meshprobe can be run in two ways:
- As a script: `python3 meshprobe.py <command>`
- As a module: `python3 -m meshprobe <command>`

### Basic Commands

**Listen and inspect MQTT traffic:**
```bash
python3 meshprobe.py listen --hex-dump decrypted --colored --filter text,position
```

Hex dump modes: `full`, `payload`, `encrypted`, `decrypted`, `raw`
Filter types: `text`, `position`, `nodeinfo`, `telemetry`, `routing`, `neighbor`, `map`, `encrypted`, `ascii`

**Send text message:**
```bash
python3 meshprobe.py text @da548c90 "hello" --channel 0 --hops 3
```

Optional encryption: `--openssl-password <pwd>`, `--pbkdf2-iter 10000`, `--base64`

**Publish to map:**
```bash
python3 meshprobe.py map --hex-dump
```

**Send position:**
```bash
python3 meshprobe.py position @da548c90 --randomize
```

**Broadcast node info or telemetry:**
```bash
python3 meshprobe.py nodeinfo
python3 meshprobe.py telemetry
python3 meshprobe.py telemetry:env
```

### Global Options

- `--root-topic msh/US` - Override MQTT root topic (e.g., `msh/EU_868`)
- `--psk <base64>` - Override PSK for all channels

## Configuration Files

**`server_config.json`** - MQTT broker settings (host, port, credentials)

**`node_config.json`** - Node identity and channel configuration
- `node_id` must start with `!` (e.g., `"!12345678"`)
- Define channels: `{ "0": { "name": "LongFast", "psk": "AQ==" } }`

**`client_config.json`** - Local behavior (node DB flush interval, `nodes/` directory)

## Output

Messages display with clear separators showing:
- MQTT topic
- From/to node IDs
- Channel and packet ID
- Message type and parsed content
- Optional hex dumps (when enabled)

On exit, a summary shows packet counts by type and decryption success/failure statistics.

## Tips

- Tab completion is available with `argcomplete` for `--root-topic` and filter options
- Node data is automatically logged to the `nodes/` directory
- Use `--colored` for ANSI color output in hex dumps

## Troubleshooting

**Import errors:**
```bash
pip install meshtastic paho-mqtt
```

**Connection failures:**
- Verify broker settings in `server_config.json`
- Check network access to MQTT host/port
- Ensure credentials are correct
