##
## LS_COLORS
##
## 必须排在下面的 Completion Styles 之前:那边的 list-colors 是把 $LS_COLORS 的
## 当前值拆开存进 zstyle,不是留一个引用。之前这段在文件末尾,于是第一个登录 shell
## 里补全菜单拿到的是空值(嵌套 shell 从父进程继承,所以一直没被发现)。

export LS_COLORS='*.7z=38;5;40:*.WARC=38;5;40:*.a=38;5;40:*.arj=38;5;40:*.bz2=38;5;40:*.cpio=38;5;40:*.gz=38;5;40:*.lrz=38;5;40:*.lz=38;5;40:*.lzma=38;5;40:*.lzo=38;5;40:*.rar=38;5;40:*.s7z=38;5;40:*.sz=38;5;40:*.tar=38;5;40:*.tbz=38;5;40:*.tgz=38;5;40:*.warc=38;5;40:*.xz=38;5;40:*.z=38;5;40:*.zip=38;5;40:*.zipx=38;5;40:*.zoo=38;5;40:*.zpaq=38;5;40:*.zst=38;5;40:*.zstd=38;5;40:*.zz=38;5;40:*@.service=38;5;45:*AUTHORS=38;5;220;1:*CHANGES=38;5;220;1:*CONTRIBUTORS=38;5;220;1:*COPYING=38;5;220;1:*COPYRIGHT=38;5;220;1:*CodeResources=38;5;239:*Dockerfile=38;5;155:*HISTORY=38;5;220;1:*INSTALL=38;5;220;1:*LICENSE=38;5;220;1:*LS_COLORS=48;5;89;38;5;197;1;3;4;7:*MANIFEST=38;5;243:*Makefile=38;5;155:*NOTICE=38;5;220;1:*PATENTS=38;5;220;1:*PkgInfo=38;5;239:*README=38;5;220;1:*README.md=38;5;220;1:*README.rst=38;5;220;1:*VERSION=38;5;220;1:*authorized_keys=1:*cfg=1:*conf=1:*config=1:*core=38;5;241:*id_dsa=38;5;192;3:*id_ecdsa=38;5;192;3:*id_ed25519=38;5;192;3:*id_rsa=38;5;192;3:*known_hosts=1:*lock=38;5;248:*lockfile=38;5;248:*pm_to_blib=38;5;240:*rc=1:*.1p=38;5;7:*.32x=38;5;213:*.3g2=38;5;115:*.3ga=38;5;137;1:*.3gp=38;5;115:*.3p=38;5;7:*.82p=38;5;121:*.83p=38;5;121:*.8eu=38;5;121:*.8xe=38;5;121:*.8xp=38;5;121:*.A64=38;5;213:*.BAT=38;5;172:*.BUP=38;5;241:*.C=38;5;81:*.CFUserTextEncoding=38;5;239:*.DS_Store=38;5;239:*.F=38;5;81:*.F03=38;5;81:*.F08=38;5;81:*.F90=38;5;81:*.F95=38;5;81:*.H=38;5;110:*.IFO=38;5;114:*.JPG=38;5;97:*.M=38;5;110:*.MOV=38;5;114:*.PDF=38;5;141:*.PFA=38;5;66:*.PL=38;5;160:*.R=38;5;49:*.RData=38;5;178:*.Rproj=38;5;11:*.S=38;5;110:*.S3M=38;5;137;1:*.SKIP=38;5;244:*.TIFF=38;5;97:*.VOB=38;5;115;1:di=34:do=38;5;127:ex=38;5;208;1:pi=38;5;126:fi=0:ln=target:mh=38;5;222;1:no=0:or=48;5;196;38;5;232;1:ow=38;5;220;1:sg=48;5;3;38;5;0:su=38;5;220;1;3;100;1:so=38;5;197:st=38;5;86;48;5;234:tw=48;5;235;38;5;139;3:'

##
## Completion Styles
##

zstyle ':completion:*:git-checkout:*' sort false
zstyle ':completion:*:descriptions' format '[%d]'
zstyle ':completion:*' list-colors ${(s.:.)LS_COLORS}
zstyle ':fzf-tab:complete:cd:*' fzf-preview 'eza -1 --color=always $realpath'
zstyle ':fzf-tab:*' switch-group ',' '.'

# sops 自带的 _sops(sops 包里的 share/zsh/site-functions/_sops)是 urfave/cli 那套
# 通用脚本,有个硬毛病:
#
#   opts=(...$(sops --generate-bash-completion)...)
#   if [[ "${opts[1]}" != "" ]]; then _describe 'values' opts
#   else _files
#
# 而 sops 无论在什么位置都会返回 16 行子命令,于是 else 里那个 _files 一次都执行不到
# —— `sops <TAB>` 只给子命令,补不出文件路径。这里改成两种候选都给。
_sops() {
  local -a opts
  local cur=${words[-1]}
  if [[ $cur == -* ]]; then
    opts=("${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ${words[@]:0:#words[@]-1} ${cur} --generate-bash-completion 2>/dev/null)}")
    [[ -n ${opts[1]} ]] && _describe -t options 'option' opts
    return
  fi
  opts=("${(@f)$(_CLI_ZSH_AUTOCOMPLETE_HACK=1 ${words[@]:0:#words[@]-1} --generate-bash-completion 2>/dev/null)}")
  [[ -n ${opts[1]} ]] && _describe -t commands 'command' opts
  _files
}
compdef _sops sops

##
## Utility Functions
##

_sudo_replace_buffer() {
  local old=$1 new=$2 space=${2:+ }
  if [[ $CURSOR -le ${#old} ]]; then
    BUFFER="${new}${space}${BUFFER#$old }"
    CURSOR=${#new}
  else
    LBUFFER="${new}${space}${LBUFFER#$old }"
  fi
}

_sudo_command_line() {
  [[ -z $BUFFER ]] && LBUFFER="$(fc -ln -1)"
  local WHITESPACE=""
  if [[ ${LBUFFER:0:1} = " " ]]; then
    WHITESPACE=" "
    LBUFFER="${LBUFFER:1}"
  fi
  {
    local EDITOR=${SUDO_EDITOR:-${VISUAL:-$EDITOR}}
    if [[ -z "$EDITOR" ]]; then
      case "$BUFFER" in
        sudo\ -e\ *) _sudo_replace_buffer "sudo -e" "" ;;
        sudo\ *) _sudo_replace_buffer "sudo" "" ;;
        *) LBUFFER="sudo $LBUFFER" ;;
      esac
      return
    fi
    local cmd="${${(Az)BUFFER}[1]}"
    local realcmd="${${(Az)aliases[$cmd]}[1]:-$cmd}"
    local editorcmd="${${(Az)EDITOR}[1]}"
    if [[ "$realcmd" = (\$EDITOR|$editorcmd|${editorcmd:c}) \
      || "${realcmd:c}" = ($editorcmd|${editorcmd:c}) ]] \
      || builtin which -a "$realcmd" | command grep -Fx -q "$editorcmd"; then
      _sudo_replace_buffer "$cmd" "sudo -e"
      return
    fi
    case "$BUFFER" in
      $editorcmd\ *) _sudo_replace_buffer "$editorcmd" "sudo -e" ;;
      \$EDITOR\ *) _sudo_replace_buffer '$EDITOR' "sudo -e" ;;
      sudo\ -e\ *) _sudo_replace_buffer "sudo -e" "$EDITOR" ;;
      sudo\ *) _sudo_replace_buffer "sudo" "" ;;
      *) LBUFFER="sudo $LBUFFER" ;;
    esac
  } always {
    LBUFFER="${WHITESPACE}${LBUFFER}"
    zle redisplay
  }
}

_vi_search_fix() {
  zle vi-cmd-mode
  zle .vi-history-search-backward
}

# 这一轮删掉的抄来的函数:
#   toppy        history 词频统计的小玩具,1688 行历史里一次没用过
#   git-svn      从 svn 仓库导出子目录 —— 这台机器上连 svn 都没有
#   _smooth_fzf  在 ~/.config 里 fzf 挑文件编辑,连同它占的 ^o 键位一起去掉。
#                它原来是 `bindkey -s`,用过的话会在 history 里留下 _smooth_fzf,
#                实际是 0 次。
#
# proxy / unproxy 留着:这台 mac 的 history 里没有,但它是按机器分的 —— 而且这类
# 网络逃生口不该因为"最近没用"就删。

proxy() {
  local proxy_address="http://127.0.0.1:7890"
  export http_proxy="${proxy_address}"
  export https_proxy="${proxy_address}"
  export all_proxy="${proxy_address}"
  export HTTP_PROXY="${proxy_address}"
  export HTTPS_PROXY="${proxy_address}"
  export ALL_PROXY="${proxy_address}"
  echo "Proxy enabled (http/https/all -> ${proxy_address})"
  env | grep -i "_proxy"
}

unproxy() {
  unset http_proxy https_proxy all_proxy
  unset HTTP_PROXY HTTPS_PROXY ALL_PROXY
  echo "Proxy disabled"
}

##
## Auto eza on cd
##

autoload -Uz add-zsh-hook add-zle-hook-widget

_auto_eza_ls() {
  [[ -o interactive ]] && eza --color=auto --icons
}

add-zsh-hook chpwd _auto_eza_ls

##
## ZLE Widget Registration
##

zle -N _vi_search_fix
zle -N _sudo_command_line

##
## Vi-mode 光标形状
##
## 用 add-zle-hook-widget 而不是 zle -N zle-keymap-select / zle-line-init:后者是
## 独占这两个名字,谁最后定义谁说了算,会把已经挂在上面的插件钩子顶掉。

_cursor_shape_keymap_select() {
  if [[ ${KEYMAP} == vicmd ]]; then
    echo -ne '\e[1 q'   # 块状
  else
    echo -ne '\e[5 q'   # 竖线
  fi
}
add-zle-hook-widget keymap-select _cursor_shape_keymap_select

_cursor_shape_line_init() {
  echo -ne '\e[5 q'
}
add-zle-hook-widget line-init _cursor_shape_line_init

echo -ne '\e[5 q'

##
## Keybindings
##

bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line

# ^K 原来绑的是 `bindkey -s '^K' 'ls^M'`,两个毛病:占掉了 kill-line 这个位置,
# 而且 -s 是往输入缓冲里塞字符 —— 行上已经打了一半东西时按下去,会把 ls 和一个
# 回车插进当前命令里直接执行。想列目录直接敲 ls 就是了。
#
# 这里显式绑 kill-line 而不是"解绑让它回到默认":默认键位是 viins,那张表里 ^K
# 本来就没有 kill-line(解绑只会掉回 self-insert)。
bindkey '^K' kill-line

# Prepend sudo (double Escape)
bindkey -M emacs '\e\e' _sudo_command_line
bindkey -M vicmd '\e\e' _sudo_command_line
bindkey -M viins '\e\e' _sudo_command_line

# Fix backspace and other stuff in vi-mode
bindkey -M viins '\e/' _vi_search_fix
bindkey "^?" backward-delete-char
bindkey "^H" backward-delete-char
bindkey "^U" backward-kill-line

umask 022

##
## Man pager with colors
##

export LESS="--RAW-CONTROL-CHARS"
export MANPAGER="less -s -M +Gg"
export LESS_TERMCAP_mb=$'\e[1;32m'
export LESS_TERMCAP_md=$'\e[1;32m'
export LESS_TERMCAP_me=$'\e[0m'
export LESS_TERMCAP_se=$'\e[0m'
export LESS_TERMCAP_so=$'\e[01;33m'
export LESS_TERMCAP_ue=$'\e[0m'
export LESS_TERMCAP_us=$'\e[1;4;31m'

##
## Elan (Lean theorem prover)
##

if [ -f "$HOME/.elan/env" ]; then
  . "$HOME/.elan/env"
fi

##
## macOS specific
##

if [ "$(uname)" = "Darwin" ]; then
  source ~/.orbstack/shell/init.zsh 2>/dev/null || :
  alias matlabcli="/Applications/MATLAB_R2025a.app/bin/matlab -nodesktop -nosplash"
  export HOMEBREW_BOTTLE_DOMAIN=https://mirror.sjtu.edu.cn/homebrew-bottles

  # 这里原来是 eval "$(brew shellenv)" —— 每次开 shell fork 一个 bash 脚本,它自己
  # 再 fork 一次 /usr/libexec/path_helper,实测 ~55ms,而输出是常量。
  #
  # 顺带甩掉 path_helper:它会按 /etc/paths 重排 PATH,把 /usr/bin 顶到 nix 前面。
  #
  # path/fpath 用数组前插,不是 export PATH="...:$PATH" —— 后者在嵌套 shell 里
  # 会一层层叠上去(rustup 那条以前就是这么重复的)。
  if [ "$(uname -m)" = "x86_64" ]; then
    export HOMEBREW_PREFIX="/usr/local"
  else
    export HOMEBREW_PREFIX="/opt/homebrew"
    path=("/opt/homebrew/opt/rustup/bin" $path)
  fi
  export HOMEBREW_CELLAR="$HOMEBREW_PREFIX/Cellar"
  export HOMEBREW_REPOSITORY="$HOMEBREW_PREFIX"
  export INFOPATH="$HOMEBREW_PREFIX/share/info:${INFOPATH:-}"
  path=("$HOMEBREW_PREFIX/bin" "$HOMEBREW_PREFIX/sbin" $path)
  fpath=("$HOMEBREW_PREFIX/share/zsh/site-functions" $fpath)
fi

# vim:ft=zsh:nowrap
