#!/usr/bin/env zsh
###############################################################################
# Oversight Shell Wrapper v0.3.0
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Interecepts risky commands and routes scripts to the 
#               Oversight Analysis TUI.
###############################################################################

oversight() {
    local wrapper="$HOME/arch-projects/oversight/target/release/oversight"
    local log_root="$HOME/oversight/logs"
    
    if [[ -z "$1" ]]; then
        echo "Usage: sbox <script_path_or_url>"
        return 1
    fi

    # Create session log directory if needed
    mkdir -p "$log_root"

    # Launch the Rust TUI directly. 
    # The Rust binary now handles the UI, Fetching, and Analysis.
    "$wrapper" "$@"
}

# This function watches every command you type in your shell
_oversight_preexec() {
    local user_cmd="$1"
    # Detects pipes to shell or destructive deletions
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"

    if [[ "$user_cmd" =~ $risky_regex ]]; then
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command pattern detected."
        
        local choice
        choice=$(echo -e "Audit Command\nRun Normally\nAbort" | fzf \
            --height=10 \
            --header="Analyze this command before execution?" \
            --layout=reverse --border=rounded)

        case "$choice" in
            "Audit Command")
                echo -e "\033[1;34m[Oversight]\033[0m Passing to auditor..."
                
                # If it's a curl/wget pipe, we try to extract the URL to audit it
                if [[ "$user_cmd" =~ "(https?://[^ ]+)" ]]; then
                    local remote_url="${match[1]}"
                    sbox "$remote_url"
                else
                    # Otherwise, just audit the raw command string if possible
                    # (Future update: allow passing raw strings to sbox)
                    echo "Audit for raw strings coming in v0.3.1"
                fi
                return 1 # Stop the original command from running
                ;;
            "Abort"|"")
                return 1 # Stop the command
                ;;
            "Run Normally")
                return 0 # Let the command proceed
                ;;
        esac
    fi
}

# To enable the automatic interceptor, add this to your .zshrc:
# add-zsh-hook preexec _oversight_preexec
