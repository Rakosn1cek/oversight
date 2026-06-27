###############################################################################
# Oversight Shell Wrapper (Fish)
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

    # Direct execution is preferred over eval in Fish
    $binary $argv
end

# Fish event listener for standalone download utility commands
function _oversight_preexec --on-event fish_preexec
    set -l user_cmd $argv[1]
    set -l risky_regex "((curl|wget).*https?://[^ ]+|rm +-rf +/)"

    if string match -r $risky_regex $user_cmd > /dev/null
        while true
            echo -e "\n\e[1;33m[!] Oversight:\e[0m Risky command pattern detected."
            set -l choice (echo -e "Analyse Command\nRun Normally\nAbort" | fzf \
                --height=10 \
                --header="Analyse this command before execution?" \
                --layout=reverse --border=rounded)

            switch "$choice"
                case "Analyse Command"
                    echo -e "\e[1;34m[Oversight]\e[0m Passing to auditor..."
       
                    if string match -r "https?://[^ ]+" $user_cmd | read -l remote_url
                        oversight $remote_url
                        clear
                    else
                        echo "Audit for raw strings is planned for a future release."
                        commandline -f cancel
                        return 1
                    end
                case "Run Normally"
                    return 0
                case "Abort" ""
                    echo -e "\e[1;31m[-] Installation aborted.\e[0m"
                    commandline -r ""
                    commandline -f cancel
                    commandline -f repaint
                    return 1
            end
        done
    end
end
