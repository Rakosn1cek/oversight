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
    # Prevention of recursion and ignoring the auditor itself
    [[ "$BASH_COMMAND" == "$PROMPT_COMMAND" ]] && return
    [[ "$BASH_COMMAND" == "oversight"* ]] && return

    # Detection for piping remote content to common interpreters
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh| *python| *ruby| *perl)|rm +-rf +/"
    
    if [[ "$BASH_COMMAND" =~ $risky_regex ]]; then
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command pattern detected."
        
        # Integration with fzf for a consistent selection interface
        if command -v fzf >/dev/null 2>&1; then
            local choice
            choice=$(echo -e "Analyse Command\nRun Normally\nAbort" | fzf \
                --height=10 \
                --header="Analyse this command before execution?" \
                --layout=reverse --border=rounded)
        else
            # Fallback to standard read if fzf is missing
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
                
                # URL extraction using BASH_REMATCH for local processing
                if [[ "$BASH_COMMAND" =~ (https?://[^ ]+) ]]; then
                    oversight "${BASH_REMATCH[1]}"
                else
                    echo "Audit for raw strings is planned for a future release."
                fi
                # Returning a non-zero status in a DEBUG trap with extdebug enabled cancels the command
                return 1 
                ;;
            "Run Normally")
                return 0 
                ;;
            *)
                return 1 
                ;;
        esac
    fi
}

# Enabling extended debug is necessary for the trap return code to control command execution
shopt -s extdebug
trap '_oversight_preexec' DEBUG
