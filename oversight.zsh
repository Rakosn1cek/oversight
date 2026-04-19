#!/usr/bin/env zsh
###############################################################################
# Oversight Shell Wrapper
#
# Author:      Lukas Grumlik - Rakosn1ek
# Date:        2026-04-19
# Version:     0.1.0
#
# Description: 
# This wrapper manages the user interface for Oversight. It captures scan 
# results, provides an interactive selection menu via fzf, and handles 
# the real-time filtering of blocked system actions during sandboxed 
# execution.
#
# Usage:       sbox <script_to_run>
###############################################################################

sbox() {
    local wrapper="$HOME/arch-projects/oversight/target/release/oversight"
    local session_tmp=$(mktemp -d /tmp/oversight_XXXXXX)
    trap 'rm -rf "$session_tmp"' EXIT

    # Capture scan findings
    local scan_results
    scan_results=$("$wrapper" -- "$@" 2>&1)
    local ret=$?

    if [[ $ret -eq 10 ]]; then
        local action
        # Note: Using a literal newline in the header string here
        action=$(echo -e "Sandbox\nLive\nAnalyze\nAbort" | fzf \
            --height=20 \
            --header-first \
            --header="[!] SECURITY ALERT - Findings for $1:
$scan_results" \
            --layout=reverse \
            --border=rounded \
            --prompt="Action required > ")

        case "$action" in
            "Sandbox")
                local audit_log=$(mktemp)
                
                # Using 'stdbuf' to ensure the output isn't buffered
                # Redirect 2>&1 to merge errors into the main stream 
                # Then using 'awk' to act as a real-time filter
                OVERSIGHT_TMP="$session_tmp" "$wrapper" --no-scan -w . -w "$session_tmp" -- "$@" 2>&1 | while read -r line || [[ -n "$line" ]]; do
                    if [[ "$line" == *"Permission denied"* ]]; then
                        # If it's a block, send it to the bucket
                        echo "$line" >> "$audit_log"
                    else
                        # If it's normal output (CPU/RAM), print it now
                        echo "$line"
                    fi
                done
            
                # Final Audit Report
                if [[ -s "$audit_log" ]]; then
                    echo -e "\n\033[1;34m[i] Oversight Security Audit:\033[0m"
                    echo -e "\033[1;31mThe following unauthorised actions were intercepted and blocked:\033[0m"
                    
                    # Clean up the shell noise and show the unique blocks
                    sed -E 's/^.*line [0-9]+: //' "$audit_log" | sed -E 's/^[: ]+//' | sort -u | while read -r line; do
                        echo -e "  \033[1;33m➜\033[0m $line"
                    done
                fi
                rm -f "$audit_log"
                ;;
            "Analyze")
                ${EDITOR:-nano} "$1"
                ;;
        esac
        return
    fi

    # Clean run path
    OVERSIGHT_TMP="$session_tmp" "$wrapper" -w . -w "$session_tmp" -- "$@"
}

_oversight_preexec() {
    local user_cmd="$1"
    local risky_regex="(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"

    if [[ "$user_cmd" =~ $risky_regex ]]; then
        echo -e "\n\033[1;33mOversight:\033[0m Risky command detected."
        
        local choice=$(echo -e "Sandbox Execution\nRun Normally\nAbort" | fzf \
            --height=10 \
            --header="Protect your system?" \
            --layout=reverse --border=rounded)

        case "$choice" in
            "Sandbox Execution")
                echo -e "\033[1;34m[Oversight]\033[0m Jailing process..."
                # Using the same 'sbox' logic here for consistency
                sbox zsh -c "$user_cmd"
                return 1
                ;;
            "Abort"|"")
                return 1
                ;;
        esac
    fi
}
