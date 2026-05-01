###############################################################################
# Oversight Shell Wrapper v0.4.1 (Fish)
#
# Author:       Lukas Grumlik - Rakosn1cek
# Description:  Intercepts risky commands and routes them to the 
#               Oversight Analysis TUI.
###############################################################################

function oversight --description 'Security Intelligence & Audit Engine'
    set -l binary "$HOME/.local/bin/oversight"
    
    if test -z "$argv[1]"
        echo "Usage: oversight <script_path_or_url>"
        return 1
    end

    eval $binary $argv
end

# Fish event listener for risky commands
function _oversight_preexec --on-event fish_preexec
    set -l user_cmd $argv[1]
    set -l risky_regex "(curl|wget).+\|( *bash| *sh| *zsh)|rm +-rf +/"

    if string match -r $risky_regex $user_cmd > /dev/null
        echo -e "\n\e[1;33m[!] Oversight:\e[0m Risky command pattern detected."
        
        set -l choice (echo -e "Audit Command\nRun Normally\nAbort" | fzf \
            --height=10 \
            --header="Analyze this command before execution?" \
            --layout=reverse --border=rounded)

        switch $choice
            case "Audit Command"
                echo -e "\e[1;34m[Oversight]\e[0m Passing to auditor..."
                if string match -r "(https?://[^ ]+)" $user_cmd | read -l remote_url
                    oversight $remote_url
                else
                    echo "Audit for raw strings coming in v0.4.0"
                end
                # Fish does not easily allow cancelling the current command from a hook
                # without using 'commandline -f repaint', so manual abort is advised.
            case "Abort" ""
                # To truly abort in Fish, one would typically clear the commandline
                commandline -f repaint
            case "Run Normally"
                return 0
        end
    end
end
