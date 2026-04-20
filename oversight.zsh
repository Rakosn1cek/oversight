#!/usr/bin/env zsh
###############################################################################
# Oversight Shell Wrapper
#
# Author:      Lukas Grumlik - Rakosn1ek
# Date:        2026-04-19
# Version:     0.1.1
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
    setopt localoptions rmstarsilent
    local wrapper="$HOME/arch-projects/oversight/target/release/oversight"
    local log_root="$HOME/oversight/logs"
    
    # 1. THE JANITOR CHECK
    # Check if the directory exists and has any files in it
    if [[ -d "$log_root" && -n "$(ls -A "$log_root")" ]]; then
        echo -en "\033[1;33m[?]\033[0m Previous logs found. Clear them before starting? (y/N): "
        read -k 1 res
        echo "" # Just a newline for cleanliness
        if [[ "$res" == "y" || "$res" == "Y" ]]; then
            rm -rf "$log_root"/*
            echo -e "\033[1;32m[✓]\033[0m Logs cleared."
        fi
    fi

    # Create session-specific folder
    local session_id=$(date +%Y%m%d_%H%M%S)
    local session_dir="$log_root/session_$session_id"
    mkdir -p "$session_dir"

    # Capture scan findings
    local scan_results
    scan_results=$("$wrapper" -- "$@" 2>&1)
    local ret=$?

    if [[ $ret -eq 10 ]]; then
        local action
        action=$(echo -e "Sandbox\nLive\nAnalyze\nAbort" | fzf \
            --height=20 \
            --header-first \
            --header="[!] SECURITY ALERT - Findings for $1:
$scan_results" \
            --footer="Session Log: $session_dir" \
            --layout=reverse \
            --border=rounded \
            --prompt="Action required > ")

        case "$action" in
            "Sandbox")
                local audit_log="$session_dir/audit.log"
                
                # Using our perfected filter logic
	            {
	                OVERSIGHT_TMP="$session_dir" "$wrapper" --no-scan -r . -w "$session_dir" -- "$@"
	                wait # Ensure background curl/tasks finish their attempts
	            } 2>&1 | while read -r line || [[ -n "$line" ]]; do
	                if [[ "$line" == *"Permission denied"* || \
	                      "$line" == *"Operation not permitted"* || \
	                      "$line" == *"it is dangerous to operate"* || \
	                      "$line" == *"use --no-preserve-root"* ]]; then
	                    echo "$line" >> "$audit_log"
	                else
	                    echo "$line"
	                fi
	            done

                if [[ -s "$audit_log" ]]; then
                    echo -e "\n\033[1;34m[i] Oversight Security Audit:\033[0m"
                    echo -e "\033[1;31mThe following unauthorised actions were intercepted and blocked:\033[0m"
                    
                    sed -E 's/^.*line [0-9]+: //' "$audit_log" | sed -E 's/^[: ]+//' | sort -u | while read -r line; do
                        echo -e "  \033[1;33m➜\033[0m $line"
                    done
                fi
                ;;
            "Live") "$@" ;;
            "Analyze") ${EDITOR:-nano} "$1" ;;
        esac
        return
    fi

    # Path for clean scripts
    OVERSIGHT_TMP="$session_dir" "$wrapper" -w . -w "$session_dir" -- "$@"
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
