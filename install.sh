#!/usr/bin/env bash
###############################################################################
# Oversight Installer v0.4.0
#
# Author: Lukas Grumlik - Rakosn1cek
# Distro-agnostic, shell-aware setup script.
###############################################################################

set -e

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==>${NC} Starting Oversight Installation..."

# 1. DEPENDENCY CHECK
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}[!] Error:${NC} Rust/Cargo not found. Please install it via 'rustup.rs'."
    exit 1
fi

# 2. BUILD
echo -e "${BLUE}==>${NC} Compiling Oversight engine (this may take a few minutes)..."
cargo build --release

# 3. BINARY DEPLOYMENT
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
cp target/release/oversight "$BIN_DIR/oversight"
echo -e "${GREEN}[✓]${NC} Binary deployed to $BIN_DIR"

# 4. DATA & SHELL INTEGRATION
SUPPORT_DIR="$HOME/.local/share/oversight"
mkdir -p "$SUPPORT_DIR"

# DEPLOY RULES DATA (Crucial for Phase 1)
if [ -f "rules.json" ]; then
    cp rules.json "$SUPPORT_DIR/rules.json"
    echo -e "${GREEN}[✓]${NC} Security rules deployed to $SUPPORT_DIR"
else
    echo -e "${RED}[!] Warning:${NC} rules.json not found in current directory. Tool will use embedded defaults."
fi

CURRENT_SHELL=$(basename "$SHELL")
CONFIG_FILE=""
HOOK_SOURCE=""

case "$CURRENT_SHELL" in
    zsh)
        CONFIG_FILE="$HOME/.zshrc"
        HOOK_SOURCE="oversight.zsh"
        ;;
    bash)
        CONFIG_FILE="$HOME/.bashrc"
        HOOK_SOURCE="oversight.bash"
        ;;
    fish)
        CONFIG_FILE="$HOME/.config/fish/config.fish"
        HOOK_SOURCE="oversight.fish"
        ;;
    *)
        echo -e "${YELLOW}[!] Warning:${NC} Unsupported shell ($CURRENT_SHELL). Manual setup required."
        ;;
esac

if [ -n "$CONFIG_FILE" ]; then
    # Deploy shell-specific hooks
    if [ -f "$HOOK_SOURCE" ]; then
        cp "$HOOK_SOURCE" "$SUPPORT_DIR/"
    else
         echo -e "${RED}[!] Error:${NC} $HOOK_SOURCE not found. Hook deployment failed."
    fi

    # Check if already integrated
    if ! grep -q "oversight" "$CONFIG_FILE"; then
        echo -e "${BLUE}==>${NC} Integrating with $CONFIG_FILE..."
        echo "" >> "$CONFIG_FILE"
        echo "# --- Oversight Security Tool ---" >> "$CONFIG_FILE"
        
        if [ "$CURRENT_SHELL" == "zsh" ]; then
            echo "source $SUPPORT_DIR/oversight.zsh" >> "$CONFIG_FILE"
            echo "add-zsh-hook preexec _oversight_preexec" >> "$CONFIG_FILE"
        elif [ "$CURRENT_SHELL" == "bash" ]; then
            echo "source $SUPPORT_DIR/oversight.bash" >> "$CONFIG_FILE"
        elif [ "$CURRENT_SHELL" == "fish" ]; then
            echo "source $SUPPORT_DIR/oversight.fish" >> "$CONFIG_FILE"
        fi
        
        echo -e "${GREEN}[✓]${NC} Shell hooks added to $CONFIG_FILE."
    else
        echo -e "${YELLOW}[i]${NC} Oversight already integrated in $CONFIG_FILE."
    fi
fi

# 5. FINAL VERDICT
echo -e "\n${GREEN}Installation Complete!${NC}"
echo -e "Please restart your terminal or run: ${YELLOW}source $CONFIG_FILE${NC}"
