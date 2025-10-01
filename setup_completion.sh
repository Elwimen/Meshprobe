#!/bin/bash

# Setup argcomplete for mqtt_client.py

echo "Setting up tab completion for mqtt_client.py..."

# Install argcomplete if not already installed
if ! python3 -c "import argcomplete" 2>/dev/null; then
    echo "Installing argcomplete..."
    pip install argcomplete
fi

# Get the absolute path to mqtt_client.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQTT_CLIENT="$SCRIPT_DIR/mqtt_client.py"

# Add completion to .bashrc
COMPLETION_LINE="eval \"\$(register-python-argcomplete mqtt_client.py)\""

if ! grep -q "register-python-argcomplete mqtt_client.py" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Tab completion for mqtt_client.py" >> ~/.bashrc
    echo "$COMPLETION_LINE" >> ~/.bashrc
    echo "Added completion to ~/.bashrc"
else
    echo "Completion already exists in ~/.bashrc"
fi

echo "Done! Please run: source ~/.bashrc"
