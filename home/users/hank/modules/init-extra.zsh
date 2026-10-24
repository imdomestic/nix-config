#
# 这里只放 home-manager 没有对应 option 的东西。
#
# programs.zsh 的 option 表里没有 zstyle、没有 bindkey、没有 zle widget、也没有
# chpwd hook —— 这几类只能是 zsh 代码。而函数体、环境变量、平台分支都已经搬到
# default.nix 的 siteFunctions / home.sessionVariables / lib.optionalString 去了,
# 所以这个文件剩下的都是"注册和绑定",没有实现。
#
# 保持独立 .zsh 文件而不是塞进 initContent 字符串的理由:Nix 字符串里写 zsh 要
# 处理 ''${ 转义,还会丢掉 `zsh -n` 语法检查和编辑器高亮。
#

##
## Completion Styles
##

zstyle ':completion:*:git-checkout:*' sort false
zstyle ':completion:*:descriptions' format '[%d]'
zstyle ':fzf-tab:complete:cd:*' fzf-preview 'eza -1 --color=always $realpath'
zstyle ':fzf-tab:*' switch-group ',' '.'

# sops 包自带的 _sops(urfave/cli 那套通用脚本)先跑 `sops --generate-bash-completion`
# 要候选,只要非空就 _describe 收工 —— 而 sops 在任何位置都会返回 16 行子命令,于是
# 它那个 else 分支里的 _files 一次都执行不到,`sops <TAB>` 补不出文件路径。
#
# 替代实现在 default.nix 的 siteFunctions 里,名字**不能**也叫 _sops:siteFunctions
# 是往 ~/.nix-profile/share/zsh/site-functions/ 写文件的,而 sops 包自己占着那个文件名,
# 同名会在 profile 里撞车。
compdef _sops_files sops

##
## Hook / widget 注册
##
## 实现都在 siteFunctions 里,这里只是挂上去。add-zle-hook-widget 会自己处理
## autoload 和 zle -N(见它的注释:"if the WIDGET is not already defined, a function
## having the same name is marked for autoload ... The WIDGET is then created with
## zle -N"),所以光标那两个不用再手写 zle -N。
##
## 用 add-zle-hook-widget 而不是 zle -N zle-keymap-select / zle-line-init:后者独占
## 这两个名字,谁最后定义谁说了算,会把已经挂在上面的插件钩子顶掉 —— 实测
## zsh-syntax-highlighting 的 line-pre-redraw / line-finish 正和它们共存。

autoload -Uz add-zsh-hook add-zle-hook-widget

add-zsh-hook chpwd _auto_eza_ls

zle -N _vi_search_fix
zle -N _sudo_command_line

add-zle-hook-widget keymap-select _cursor_shape_keymap_select
add-zle-hook-widget line-init _cursor_shape_line_init

# 进入 shell 时先摆成竖线(line-init 钩子要等第一次画提示符才触发)
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

##
## 其余
##

umask 022

# LESS_TERMCAP_* 是唯一没搬进 home.sessionVariables 的一组环境变量:它们的值必须是
# 真的 ESC 字节,而 sessionVariables 生成的是 POSIX sh 的 export NAME="value",
# 写不出 $'\e' 这种 zsh 专有引用,除非在 .nix 里塞裸 0x1B —— 那个更难维护。
# (LESS / MANPAGER 没有转义,已经搬走了。)
export LESS_TERMCAP_mb=$'\e[1;32m'
export LESS_TERMCAP_md=$'\e[1;32m'
export LESS_TERMCAP_me=$'\e[0m'
export LESS_TERMCAP_se=$'\e[0m'
export LESS_TERMCAP_so=$'\e[01;33m'
export LESS_TERMCAP_ue=$'\e[0m'
export LESS_TERMCAP_us=$'\e[1;4;31m'

# 留在这儿而不是 nix 层:elan 装在哪台机器上是运行时的事实(history 里 elan 6 次、
# lake 11 次,是在用的),不是 nix 能在求值期知道的。
if [ -f "$HOME/.elan/env" ]; then
  . "$HOME/.elan/env"
fi

# vim:ft=zsh:nowrap
