"""
Node database for storing and retrieving node information.
Each node is stored in a separate JSON file in nodes/ directory.
"""

import json
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime, timezone


class NodeDatabase:
    """Node database with one JSON file per node."""

    def __init__(self, nodes_dir: str = "nodes"):
        """
        Initialize NodeDatabase.

        Args:
            nodes_dir: Directory to store node JSON files
        """
        self.nodes_dir = Path(nodes_dir)
        self.nodes: Dict[str, dict] = {}

        # Create nodes directory if it doesn't exist
        self.nodes_dir.mkdir(exist_ok=True)

        self._load_all_nodes()

    def _load_all_nodes(self):
        """Load all node files from nodes directory."""
        node_files = list(self.nodes_dir.glob("node_*.json"))

        for node_file in node_files:
            try:
                with open(node_file, 'r') as f:
                    node_data = json.load(f)
                    node_id = node_data.get('node_id')
                    if node_id:
                        self.nodes[node_id] = node_data
            except json.JSONDecodeError as e:
                print(f"Error loading {node_file}: {e}")

        if self.nodes:
            print(f"Loaded {len(self.nodes)} nodes from {self.nodes_dir}")

    def _save_node(self, node_id: str):
        """
        Save a single node to its JSON file.

        Args:
            node_id: Node ID to save
        """
        if node_id not in self.nodes:
            return

        # Sanitize node_id for filename (replace ! with underscore)
        safe_id = node_id.replace('!', '')
        node_file = self.nodes_dir / f"node_{safe_id}.json"

        try:
            with open(node_file, 'w') as f:
                json.dump(self.nodes[node_id], f, indent=2)
        except Exception as e:
            print(f"Error saving node {node_id}: {e}")

    def add_node(self, node_id: str, long_name: str = None, short_name: str = None,
                 hw_model: int = None, macaddr: str = None):
        """
        Add or update node information.

        Args:
            node_id: Node ID (e.g., "!da5ad5ac")
            long_name: Long name
            short_name: Short name
            hw_model: Hardware model number
            macaddr: MAC address
        """
        is_new = node_id not in self.nodes
        changed = False

        if is_new:
            self.nodes[node_id] = {
                'node_id': node_id,
                'messages': [],
                'position_history': [],
                'device_metrics_history': [],
                'environment_metrics_history': []
            }
            changed = True

        node = self.nodes[node_id]

        if long_name is not None and node.get('long_name') != long_name:
            node['long_name'] = long_name
            changed = True
        if short_name is not None and node.get('short_name') != short_name:
            node['short_name'] = short_name
            changed = True
        if hw_model is not None and node.get('hw_model') != hw_model:
            node['hw_model'] = hw_model
            changed = True
        if macaddr is not None and node.get('macaddr') != macaddr:
            node['macaddr'] = macaddr
            changed = True

        if changed:
            node['last_seen'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            self._save_node(node_id)

    def add_message(self, node_id: str, text: str, direction: str = 'received',
                   encrypted: bool = False, from_node: str = None, to_node: str = None):
        """
        Add a text message to node history.

        Args:
            node_id: Node ID
            text: Message text
            direction: 'sent' or 'received'
            encrypted: Whether message was encrypted
            from_node: Sender node ID
            to_node: Recipient node ID
        """
        if node_id not in self.nodes:
            self.add_node(node_id)

        node = self.nodes[node_id]

        if 'messages' not in node:
            node['messages'] = []

        message_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'text': text,
            'direction': direction,
            'encrypted': encrypted
        }

        if from_node:
            message_entry['from'] = from_node
        if to_node:
            message_entry['to'] = to_node

        node['messages'].append(message_entry)
        node['last_seen'] = message_entry['timestamp']

        # Keep last 100 messages
        if len(node['messages']) > 100:
            node['messages'] = node['messages'][-100:]

        self._save_node(node_id)

    def add_position(self, node_id: str, latitude: float, longitude: float,
                     altitude: int, timestamp: int = None):
        """
        Add position data to node history.

        Args:
            node_id: Node ID
            latitude: Latitude
            longitude: Longitude
            altitude: Altitude in meters
            timestamp: Unix timestamp (optional)
        """
        if node_id not in self.nodes:
            self.add_node(node_id)

        node = self.nodes[node_id]

        if 'position_history' not in node:
            node['position_history'] = []

        position_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'latitude': latitude,
            'longitude': longitude,
            'altitude': altitude
        }

        if timestamp:
            position_entry['position_timestamp'] = timestamp

        node['position_history'].append(position_entry)
        node['last_position'] = position_entry.copy()
        node['last_seen'] = position_entry['timestamp']

        # Keep last 100 positions
        if len(node['position_history']) > 100:
            node['position_history'] = node['position_history'][-100:]

        self._save_node(node_id)

    def add_device_metrics(self, node_id: str, battery_level: float = None,
                          voltage: float = None, channel_utilization: float = None,
                          air_util_tx: float = None, uptime_seconds: int = None):
        """
        Add device telemetry metrics to node history.

        Args:
            node_id: Node ID
            battery_level: Battery level 0-100 or 101 for plugged in
            voltage: Voltage
            channel_utilization: Channel utilization
            air_util_tx: Air utilization TX
            uptime_seconds: Uptime in seconds
        """
        if node_id not in self.nodes:
            self.add_node(node_id)

        node = self.nodes[node_id]

        if 'device_metrics_history' not in node:
            node['device_metrics_history'] = []

        metrics = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }

        if battery_level is not None:
            metrics['battery_level'] = battery_level
        if voltage is not None:
            metrics['voltage'] = voltage
        if channel_utilization is not None:
            metrics['channel_utilization'] = channel_utilization
        if air_util_tx is not None:
            metrics['air_util_tx'] = air_util_tx
        if uptime_seconds is not None:
            metrics['uptime_seconds'] = uptime_seconds

        node['device_metrics_history'].append(metrics)
        node['last_device_metrics'] = metrics.copy()
        node['last_seen'] = metrics['timestamp']

        # Keep last 100 entries
        if len(node['device_metrics_history']) > 100:
            node['device_metrics_history'] = node['device_metrics_history'][-100:]

        self._save_node(node_id)

    def add_environment_metrics(self, node_id: str, **metrics):
        """
        Add environment telemetry metrics to node history.

        Args:
            node_id: Node ID
            **metrics: Environment metrics (temperature, humidity, pressure, etc.)
        """
        if node_id not in self.nodes:
            self.add_node(node_id)

        node = self.nodes[node_id]

        if 'environment_metrics_history' not in node:
            node['environment_metrics_history'] = []

        env_metrics = {
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        env_metrics.update(metrics)

        node['environment_metrics_history'].append(env_metrics)
        node['last_environment_metrics'] = env_metrics.copy()
        node['last_seen'] = env_metrics['timestamp']

        # Keep last 100 entries
        if len(node['environment_metrics_history']) > 100:
            node['environment_metrics_history'] = node['environment_metrics_history'][-100:]

        self._save_node(node_id)

    def get_node(self, node_id: str) -> Optional[dict]:
        """
        Get node information.

        Args:
            node_id: Node ID (e.g., "!da5ad5ac")

        Returns:
            Node info dict or None if not found
        """
        return self.nodes.get(node_id)

    def get_display_name(self, node_id: str) -> str:
        """
        Get display name for a node.

        Args:
            node_id: Node ID (e.g., "!da5ad5ac")

        Returns:
            Formatted display string like "(shai/Muadib)" or empty string if not found
        """
        node = self.nodes.get(node_id)
        if not node:
            return ""

        short = node.get('short_name', '')
        long = node.get('long_name', '')

        if short and long:
            return f" ({short}/{long})"
        elif short:
            return f" ({short})"
        elif long:
            return f" ({long})"
        else:
            return ""

    def __len__(self):
        """Return number of nodes in database."""
        return len(self.nodes)
