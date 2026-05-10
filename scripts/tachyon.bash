# SPDX-License-Identifier: MIT
# Bash completion for the tachyon CLI.
# Install: source this file from ~/.bashrc or copy to /etc/bash_completion.d/

_tachyon() {
    local cur prev words cword
    _init_completion || return

    local commands="up down show genkey pubkey backup restore version help"

    case ${cword} in
    1)
        COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
        return 0
        ;;
    2)
        case "${prev}" in
        up | down | show | backup | restore)
            # Suggest .conf files in common config dirs and CWD.
            local confdirs="/etc/tachyon /run/tachyon ."
            local files=""
            for d in $confdirs; do
                [[ -d "$d" ]] && files="$files $(compgen -G "${d}/*.conf")"
            done
            COMPREPLY=($(compgen -W "${files}" -- "${cur}"))
            return 0
            ;;
        genkey | pubkey | version | help)
            return 0
            ;;
        esac
        ;;
    esac
}

complete -F _tachyon tachyon
