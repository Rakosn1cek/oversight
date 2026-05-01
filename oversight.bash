#!/usr/bin/env bash
###############################################################################
# Oversight Shell Wrapper v0.4.1 (Bash)
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Intercepts risky commands and routes them to the 
#               Oversight Analysis TUI.
###############################################################################

oversight() {
    local binary="$HOME/.local/bin/oversight"
    
    if [[ -z "$1" ]]; then
        echo "Usage: oversight <script_path_or_url>"
        return 1
    fi

    "$binary" "$@"
}

_oversight_preexec() {
    # Avoid recursion and ignore the auditor itself
    [[ "$BASH_COMMAND" == "$PROMPT_COMMAND" ]] && return
    [[ "$BASH_COMMAND" == "oversight"* ]] && return

    # Check for risky patterns
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"
    
    if [[ "$BASH_COMMAND" =~ $risky_regex ]]; then
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command detected."
        echo -n "Audit this command? (y/n/Abort): "
        read -r choice
        
        case "$choice" in
            [yY])
                # Extract URL if present using BASH_REMATCH
                if [[ "$BASH_COMMAND" =~ (https?://[^ ]+) ]]; then
                    oversight "${BASH_REMATCH[1]}"
                else
                    echo "Audit for raw strings coming in v0.4.0"
                fi
                return 1 # Stop execution of the risky command
                ;;
            [nN]) 
                return 0 # Proceed with the command
                ;;
            *) 
                return 1 # Abort by default
                ;;
        esac
    fi
}

# Registers the function to run before every command execution
trap '_oversight_preexec' DEBUG
