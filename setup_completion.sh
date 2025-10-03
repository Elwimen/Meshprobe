#!/bin/bash

# Setup argcomplete for mesh_client.py

echo "Setting up tab completion for mesh_client.py..."

# Install argcomplete if not already installed
if ! python3 -c "import argcomplete" 2>/dev/null; then
    echo "Installing argcomplete..."
    pip install argcomplete
fi

# Get the absolute path to mesh_client.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MESH_CLIENT="$SCRIPT_DIR/mesh_client.py"

# Remove old mqtt_client.py completion from .bashrc if it exists
if grep -q "register-python-argcomplete mqtt_client.py" ~/.bashrc; then
    echo "Removing old mqtt_client.py completion from ~/.bashrc..."
    sed -i '/register-python-argcomplete mqtt_client.py/d' ~/.bashrc
    sed -i '/# Tab completion for mqtt_client.py/d' ~/.bashrc
fi

# Add completion to .bashrc
COMPLETION_LINE="eval \"\$(register-python-argcomplete mesh_client.py)\""

if ! grep -q "register-python-argcomplete mesh_client.py" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Tab completion for mesh_client.py" >> ~/.bashrc
    echo "$COMPLETION_LINE" >> ~/.bashrc
    echo "Added completion to ~/.bashrc"
else
    echo "Completion already exists in ~/.bashrc"
fi

echo "Done! Please run: source ~/.bashrc"
