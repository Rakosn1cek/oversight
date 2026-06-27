#!/usr/bin/env bash
###############################################################################
# Oversight Shell Wrapper (Bash)
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Intercepts risky commands and routes them to the 
#               Oversight Analysis TUI.
###############################################################################

oversight() {
    # Path to the permanent installation directory
    local binary="$HOME/.local/bin/oversight"
    
    if [[ -z "$1" ]]; then
        echo "Usage: oversight <script_path_or_url>"
        return 1
    fi

    "$binary" "$@"
}

_oversight_preexec() {
    [[ "$BASH_COMMAND" == "$PROMPT_COMMAND" ]] && return
    [[ "$BASH_COMMAND" == "oversight"* ]] && return

    # Matches curl/wget with a URL OR matches the destructive rm command
    local risky_regex="((curl|wget).*https?://[^ ]+|rm +-rf +/)"
    
    if [[ "$BASH_COMMAND" =~ $risky_regex ]]; then
        while true; do
            echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command pattern detected."
            
            local choice
            if command -v fzf >/dev/null 2>&1; then
                choice=$(echo -e "Analyse Command\nRun Normally\nAbort" | fzf \
                    --height=10 \
                    --header="Analyse this command before execution?" \
                    --layout=reverse --border=rounded)
            else
                echo -n "Analyse this command? (y/n/Abort): "
                read -r choice_raw
                case "$choice_raw" in
                    [yY]*) choice="Analyse Command" ;;
                    [nN]*) choice="Run Normally" ;;
                    *) choice="Abort" ;;
                esac
            fi
            
            case "$choice" in
                "Analyse Command")
                    echo -e "\033[1;34m[Oversight]\033[0m Passing to auditor..."
                    
                    if [[ "$BASH_COMMAND" =~ (https?://[^ ]+) ]]; then
                        oversight "${BASH_REMATCH[1]}"
                        clear
                    else
                        echo "Audit for raw strings is planned for a future release."
                        kill -INT $$
                        return 1
                    fi
                    ;;
                "Run Normally")
                    return 0
                    ;;
                *)
                    echo -e "\033[1;31m[-] Installation aborted.\033[0m"
                    kill -INT $$
                    return 1
                    ;;
            esac
        done
    fi
}

# Enabling extended debug is necessary for the trap return code to control command execution
shopt -s extdebug
trap '_oversight_preexec' DEBUG
