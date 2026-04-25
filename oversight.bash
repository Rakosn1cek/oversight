###############################################################################
# Oversight Bash Hook v0.3.0
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Interecepts risky commands and routes scripts to the 
#               Oversight Analysis TUI.
###############################################################################

_oversight_preexec() {
    # Avoid recursion
    [[ "$BASH_COMMAND" == "$PROMPT_COMMAND" ]] && return
    [[ "$BASH_COMMAND" == "sbox"* ]] && return

    # Check for risky patterns
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"
    
    if [[ "$BASH_COMMAND" =~ $risky_regex ]]; then
        # Using a simple read loop here since fzf might not be 
        # installed on every bash system by default, but sbox uses it.
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command detected."
        echo -n "Audit this command? (y/n/Abort): "
        read -r choice
        
        case "$choice" in
            [yY])
                # Extract URL if present
                if [[ "$BASH_COMMAND" =~ (https?://[^ ]+) ]]; then
                    oversight "${BASH_REMATCH[1]}"
                fi
                return 1 # Stop execution
                ;;
            [nN]) return 0 ;; # Proceed
            *) return 1 ;;    # Abort
        esac
    fi
}

# This tells Bash to run the function before every command
trap '_oversight_preexec' DEBUG
