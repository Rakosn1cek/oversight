#!/usr/bin/env zsh
###############################################################################
# Oversight Shell Wrapper
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
    # Detection for piping remote content to common interpreters
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh| *python| *ruby| *perl)|rm +-rf +/"

    if [[ "$user_cmd" =~ $risky_regex ]]; then
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command pattern detected."
        
        local choice
        choice=$(echo -e "Analyse Command\nRun Normally\nAbort" | fzf \
            --height=10 \
            --header="Analyse this command before execution?" \
            --layout=reverse --border=rounded)

        case "$choice" in
            "Analyse Command")
                echo -e "\033[1;34m[Oversight]\033[0m Passing to auditor..."
                
                # Extract URL for remote auditing
                if [[ "$user_cmd" =~ "(https?://[^ ]+)" ]]; then
                    local remote_url="${match[1]}"
                    oversight "$remote_url"
                else
                    echo "Audit for raw strings is planned for a future release."
                fi
                return 1
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

# Ensure the hook is registered if not already present
autoload -Uz add-zsh-hook
add-zsh-hook preexec _oversight_preexec
