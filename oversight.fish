###############################################################################
# Oversight Fish Hook v0.3.0
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Interecepts risky commands and routes scripts to the 
#               Oversight Analysis TUI.
###############################################################################

function _oversight_preexec --on-event fish_preexec
    set -l user_cmd $argv[1]
    set -l risky_regex "(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"

    if string match -r $risky_regex "$user_cmd" > /dev/null
        echo -e "\n\033[1;33m[!] Oversight:\033[0m Risky command detected."
        
        # Fish users almost always have a pager/fzf style setup
        set -l choice (echo -e "Audit Command\nRun Normally\nAbort" | fzf --height=10 --header="Analyze this command?" --layout=reverse --border=rounded)

        switch "$choice"
            case "Audit Command"
                if string match -r "(https?://[^ ]+)" "$user_cmd" > /dev/null
                    set -l remote_url (string match -r "(https?://[^ ]+)" "$user_cmd")
                    oversight $remote_url
                end
                # To "stop" a command in Fish preexec, it needs to manipulate the command buffer, which is complex. 
                # Simplest way is to just kill the current command process.
                commandline -f repaint
                kill -INT %self 
            case "Abort" ""
                commandline -f repaint
                kill -INT %self
            case "Run Normally"
                return 0
        end
    end
end
