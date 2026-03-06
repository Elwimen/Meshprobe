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

# Detect shell and set RC file
CURRENT_SHELL="$(basename "$SHELL")"
case "$CURRENT_SHELL" in
    zsh)  RC_FILE="$HOME/.zshrc" ;;
    bash) RC_FILE="$HOME/.bashrc" ;;
    *)
        echo "Warning: unrecognized shell '$CURRENT_SHELL', defaulting to ~/.bashrc"
        RC_FILE="$HOME/.bashrc"
        CURRENT_SHELL="bash"
        ;;
esac

echo "Detected shell: $CURRENT_SHELL (using $RC_FILE)"

# Clean up old/stale completion entries from both rc files
for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$RC" ] || continue

    for OLD in "mesh_client.py" "mqtt_client.py"; do
        if grep -q "register-python-argcomplete $OLD" "$RC"; then
            echo "Removing old $OLD completion from $RC..."
            sed -i "/register-python-argcomplete $OLD/d" "$RC"
            sed -i "/# Tab completion for $OLD/d" "$RC"
        fi
    done

    # Remove bash-style meshprobe completions (installed by older versions of this script)
    if grep -q "register-python-argcomplete meshprobe" "$RC"; then
        echo "Removing old bash-style meshprobe completions from $RC..."
        sed -i "/register-python-argcomplete meshprobe/d" "$RC"
        sed -i "/# Tab completion for meshprobe/d" "$RC"
        sed -i "/# Tab completion for python -m meshprobe/d" "$RC"
    fi

    # Remove the bashcompinit preamble we previously added (no longer needed)
    if grep -q "# Enable bash-style completions in zsh" "$RC"; then
        echo "Removing unneeded bashcompinit preamble from $RC..."
        sed -i "/# Enable bash-style completions in zsh/d" "$RC"
        sed -i "/autoload -U bashcompinit && bashcompinit/d" "$RC"
    fi
done

# Build completion lines based on shell
if [ "$CURRENT_SHELL" = "zsh" ]; then
    # Native zsh completion via compdef — no bashcompinit needed
    SCRIPT_COMPLETION="eval \"\$(register-python-argcomplete --shell zsh meshprobe.py)\""
    # Note: --complete-arguments is bash-only; python3 -m meshprobe not supported for zsh
    MODULE_COMPLETION=""
else
    SCRIPT_COMPLETION="eval \"\$(register-python-argcomplete meshprobe.py)\""
    MODULE_COMPLETION="eval \"\$(register-python-argcomplete --complete-arguments 'python3 -m' meshprobe)\""
fi

# Add completion for meshprobe.py script
if ! grep -q "register-python-argcomplete.*meshprobe.py" "$RC_FILE" 2>/dev/null; then
    echo "" >> "$RC_FILE"
    echo "# Tab completion for meshprobe.py" >> "$RC_FILE"
    echo "$SCRIPT_COMPLETION" >> "$RC_FILE"
    echo "Added script completion to $RC_FILE"
else
    echo "Script completion already exists in $RC_FILE"
fi

# Add completion for python -m meshprobe (bash only)
if [ -n "$MODULE_COMPLETION" ]; then
    if ! grep -q "register-python-argcomplete --complete-arguments 'python3 -m' meshprobe" "$RC_FILE" 2>/dev/null; then
        echo "# Tab completion for python -m meshprobe" >> "$RC_FILE"
        echo "$MODULE_COMPLETION" >> "$RC_FILE"
        echo "Added module completion to $RC_FILE"
    else
        echo "Module completion already exists in $RC_FILE"
    fi
fi

echo ""
echo "Tab completion setup complete!"
echo ""
echo "You can now use tab completion with:"
echo "  - python3 meshprobe.py <TAB>"
if [ "$CURRENT_SHELL" != "zsh" ]; then
    echo "  - python3 -m meshprobe <TAB>"
fi
echo ""
echo "Please run: source $RC_FILE"
