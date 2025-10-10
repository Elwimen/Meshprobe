Meshtastic MQTT Tools

Small CLI toolkit to listen to, inspect, and publish Meshtastic packets over MQTT. It can:
- Subscribe to a Meshtastic MQTT broker and pretty‑print messages (with optional hex dumps)
- Send text, node info, telemetry, and position packets
- Publish your current position to map topics

Requirements
- Python 3.10+
- Packages: `paho-mqtt`, `meshtastic` (protobufs), `argcomplete` (optional for tab completion)

Quick Start
1) Create default configs in the repo directory:
   `python3 mesh_client.py --create-configs`
   This writes `server_config.json`, `node_config.json`, `client_config.json`.
2) Edit `node_config.json:1` and set a valid node id (e.g., `"!da548c90"`). Optionally set channel PSKs in `channels`.
3) Listen to messages (defaults to public broker in `server_config.json`):
   `python3 mesh_client.py listen --duration 60`

CLI Overview
- Entry point: `mesh_client.py`
- Configs: `server_config.json`, `node_config.json`, `client_config.json`
- Root topic override: `--root-topic msh/US` (or other region)
- PSK override for all channels: `--psk <base64>`

Common Commands
- Listen/inspect MQTT traffic:
  `python3 mesh_client.py listen --hex-dump decrypted --colored --filter text,position`
  Notes: `--hex-dump` supports `full|payload|encrypted|decrypted|raw`. Use `--filter`/`--filter-out` for types like `text,position,nodeinfo,telemetry,routing,neighbor,map,encrypted,ascii`.

- Send text message:
  `python3 mesh_client.py text @da548c90 "hello" --channel 0 --hops 3`
  Optional OpenSSL SALTED encryption: `--openssl-password <pwd>`; PBKDF2 tuning: `--pbkdf2-iter 10000`; Base64 on‑air: `--base64`.

- Publish to map:
  `python3 mesh_client.py map --hex-dump`

- Send position to a node:
  `python3 mesh_client.py position @da548c90 --randomize`

- Broadcast node info / telemetry:
  `python3 mesh_client.py nodeinfo`
  `python3 mesh_client.py telemetry`
  `python3 mesh_client.py telemetry:env`

Configuration
- `server_config.json:1` Broker settings. Override at runtime with `--root-topic`.
- `node_config.json:1` Node identity and defaults.
  - `node_id` must start with `!` (e.g., `"!12345678"`). Max 16 ASCII bytes as per Meshtastic protocol.
  - Channels: you can add per‑index items like `{ "0": { "name": "LongFast", "psk": "AQ==" } }`.
- `client_config.json:1` Local behavior (node DB flush interval, `nodes/` dir).

Hex Dumps and Decryption
- Use `--hex-dump` to show raw/protobuf payloads. `--colored` enables ANSI colors.
- For OpenSSL SALTED ASCII payloads, supply `--openssl-password`. You can adjust PBKDF2 iterations via `--pbkdf2-iter`.

Expected Output
- On connect: confirmation plus subscribed topic. On listen, messages are grouped with clear separators, showing topic, from/to, channel, packet id, message type, and parsed content. Hex dumps appear between separator lines when enabled. A running summary (counts by type, decrypt success/fail) prints on exit.

Tips
- Tab completion is supported if `argcomplete` is installed; it provides suggestions for `--root-topic` and filters.
- To use a different region, pass `--root-topic msh/<REGION>` (e.g., `msh/EU_868`).
- To log node data, the tool writes to the `nodes/` directory as it sees traffic.

Troubleshooting
- Import error for `meshtastic` or `paho-mqtt`: `pip install meshtastic paho-mqtt`.
- Connection failures: verify broker/credentials in `server_config.json:1` and network access to the MQTT host/port.
