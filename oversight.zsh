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
    # Matches curl/wget with a URL OR matches the destructive rm command
    local risky_regex="((curl|wget).*https?://[^ ]+|rm +-rf +/)"

    if [[ "$user_cmd" =~ $risky_regex ]]; then
        while true; do
            echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command pattern detected."
            
            local choice
            choice=$(echo -e "Analyse Command\nRun Normally\nAbort" | fzf \
                --height=10 \
                --header="Analyse this command before execution?" \
                --layout=reverse --border=rounded)

            case "$choice" in
                "Analyse Command")
                    echo -e "\033[1;34m[Oversight]\033[0m Passing to auditor..."
                    
                    if [[ "$user_cmd" =~ (https?://[^ ]+) ]]; then
                        local remote_url="${match[1]}"
                        oversight "$remote_url"
                        clear
                    else
                        echo "Audit for raw strings is planned for a future release."
                        # Send an interrupt signal to flush the shell buffer before dropping out
                        kill -INT $$
                        return 1
                    fi
                    ;;
                "Run Normally")
                    return 0
                    ;;
                "Abort"|"")
                    echo -e "\033[1;31m[-] Installation aborted.\033[0m"
                    # Send an interrupt signal to discard the pending shell print stream entirely
                    kill -INT $$
                    return 1
                    ;;
            esac
        done
    fi
}

# Ensure the hook is registered if not already present
autoload -Uz add-zsh-hook
add-zsh-hook preexec _oversight_preexec
