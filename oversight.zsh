#!/usr/bin/env zsh
###############################################################################
# Oversight Shell Wrapper v0.3.5
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Intercepts risky commands and routes them to the 
#               Oversight Analysis TUI.
###############################################################################

oversight() {
    # Point to the permanent installation directory
    local binary="$HOME/.local/bin/oversight"
    
    if [[ -z "$1" ]]; then
        echo "Usage: oversight <script_path_or_url>"
        return 1
    fi

    # Launch the Rust TUI
    "$binary" "$@"
}

# Automatic interceptor logic
_oversight_preexec() {
    local user_cmd="$1"
    # Basic detection to trigger the FZF selection
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
                
                # Extract URL for remote auditing
                if [[ "$user_cmd" =~ "(https?://[^ ]+)" ]]; then
                    local remote_url="${match[1]}"
                    # Call the function defined above
                    oversight "$remote_url"
                else
                    echo "Audit for raw strings coming in v0.4.0"
                fi
                return 1 # Prevent original command execution
                ;;
            "Abort"|"")
                return 1 
                ;;
            "Run Normally")
                return 0 
                ;;
        esac
    fi
}
