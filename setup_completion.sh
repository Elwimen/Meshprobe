#!/bin/bash

# Setup argcomplete for meshprobe

echo "Setting up tab completion for meshprobe..."

# Install argcomplete if not already installed
if ! python3 -c "import argcomplete" 2>/dev/null; then
    echo "Installing argcomplete..."
    pip install argcomplete
fi

# Get the absolute path to meshprobe.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MESHPROBE="$SCRIPT_DIR/meshprobe.py"

# Remove old completions from .bashrc if they exist
if grep -q "register-python-argcomplete mesh_client.py" ~/.bashrc; then
    echo "Removing old mesh_client.py completion from ~/.bashrc..."
    sed -i '/register-python-argcomplete mesh_client.py/d' ~/.bashrc
    sed -i '/# Tab completion for mesh_client.py/d' ~/.bashrc
fi

if grep -q "register-python-argcomplete mqtt_client.py" ~/.bashrc; then
    echo "Removing old mqtt_client.py completion from ~/.bashrc..."
    sed -i '/register-python-argcomplete mqtt_client.py/d' ~/.bashrc
    sed -i '/# Tab completion for mqtt_client.py/d' ~/.bashrc
fi

# Add completion for meshprobe.py script
SCRIPT_COMPLETION="eval \"\$(register-python-argcomplete meshprobe.py)\""

if ! grep -q "register-python-argcomplete meshprobe.py" ~/.bashrc; then
    echo "" >> ~/.bashrc
    echo "# Tab completion for meshprobe.py" >> ~/.bashrc
    echo "$SCRIPT_COMPLETION" >> ~/.bashrc
    echo "Added script completion to ~/.bashrc"
else
    echo "Script completion already exists in ~/.bashrc"
fi

# Add completion for python -m meshprobe
MODULE_COMPLETION="eval \"\$(register-python-argcomplete --complete-arguments 'python3 -m' meshprobe)\""

if ! grep -q "register-python-argcomplete --complete-arguments 'python3 -m' meshprobe" ~/.bashrc; then
    echo "# Tab completion for python -m meshprobe" >> ~/.bashrc
    echo "$MODULE_COMPLETION" >> ~/.bashrc
    echo "Added module completion to ~/.bashrc"
else
    echo "Module completion already exists in ~/.bashrc"
fi

echo ""
echo "✓ Tab completion setup complete!"
echo ""
echo "You can now use tab completion with:"
echo "  - python3 meshprobe.py <TAB>"
echo "  - python3 -m meshprobe <TAB>"
echo ""
echo "Please run: source ~/.bashrc"
