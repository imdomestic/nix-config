{
  config,
  lib,
  pkgs,
  ...
}: let
  isDarwin = pkgs.stdenv.isDarwin;
in {
  home = {
    packages =
      [
        pkgs.git
        pkgs.gnumake
        pkgs.lazygit
        pkgs.nodejs
        pkgs.pnpm
        pkgs.subversion
      ]
      ++ lib.optionals isDarwin [
        pkgs.wezterm
      ];

    sessionPath = [
      "$HOME/.local/bin"
    ];

    sessionVariables = {
      EDITOR = "nvim";
      VISUAL = "nvim";
    };
  };

  xdg.enable = true;

  xdg.configFile =
    {
      nvim.source = ./config/nvim;
    }
    // lib.optionalAttrs isDarwin {
      wezterm.source = ./config/wezterm;
    };

  programs.starship = {
    enable = true;
    enableZshIntegration = true;
    settings = {
      python.disabled = true;
    };
  };

  programs.zsh = {
    enable = true;
    dotDir = "${config.xdg.configHome}/zsh";

    autosuggestion = {
      enable = true;
      highlight = "fg=#585B70,bold";
      strategy = [
        "history"
        "completion"
      ];
    };

    syntaxHighlighting = {
      enable = true;
      highlighters = [
        "main"
        "brackets"
        "pattern"
        "cursor"
        "regexp"
        "root"
        "line"
      ];
    };

    history = {
      expireDuplicatesFirst = true;
      extended = true;
      ignoreAllDups = true;
      ignoreDups = true;
      ignoreSpace = true;
      path = "${config.xdg.cacheHome}/zsh/.zhistory";
      save = 10000;
      share = true;
      size = 10000;
    };

    historySubstringSearch.enable = true;

    shellAliases = {
      ".." = "cd ..";
      c = "clear";
      cat = "bat --color always --plain";
      commit = "git add . && git commit -m";
      fm = "y";
      g = "git";
      ga = "git add";
      gaa = "git add --all";
      gb = "git branch";
      gba = "git branch -a";
      gbd = "git branch -d";
      gc = "git commit -v";
      "gc!" = "git commit -v --amend";
      gcam = "git commit -a -m";
      gcb = "git checkout -b";
      gcl = "git clone";
      gclr = "git clone --recurse-submodules";
      gcm = "git checkout $(git_main_branch)";
      gcmsg = "git commit -m";
      gco = "git checkout";
      gd = "git diff";
      gdca = "git diff --cached";
      gds = "git diff --staged";
      gf = "git fetch";
      gfa = "git fetch --all --prune --jobs=10";
      gl = "git pull";
      glg = "git log --stat";
      glog = "git log --oneline --decorate --graph";
      gloga = "git log --oneline --decorate --graph --all";
      gp = "git push";
      gpd = "git push --dry-run";
      gpr = "git pull --rebase";
      gr = "git remote";
      grb = "git rebase";
      grba = "git rebase --abort";
      grbc = "git rebase --continue";
      grbi = "git rebase -i";
      grs = "git restore";
      grst = "git restore --staged";
      grt = "cd \"$(git rev-parse --show-toplevel || echo .)\"";
      gsb = "git status -sb";
      gsh = "git show";
      gst = "git status";
      gsta = "git stash push";
      gstl = "git stash list";
      gstp = "git stash pop";
      gsw = "git switch";
      gswc = "git switch -c";
      la = "ls -a";
      l = "ls -l";
      lg = "lazygit";
      lla = "ls -la";
      ls = "eza --color=auto --icons";
      lt = "ls --tree";
      mkdir = "mkdir -p";
      mtar = "tar -zcvf";
      mv = "mv -v";
      psg = "ps aux | grep -v grep | grep -i -e VSZ -e";
      push = "git push";
      q = "exit";
      run = "pnpm run";
      trim-all = "sudo fstrim -va";
      utar = "tar -zxvf";
      uz = "unzip";
      zr = "zip -r";
    };

    initContent = ''
      zmodload zsh/zle
      zmodload zsh/zpty
      zmodload zsh/complist

      autoload -Uz colors add-zsh-hook
      colors

      background='#1E1E2E'
      foreground='#CDD6F4'
      color8='#585B70'

      ZSH_AUTOSUGGEST_USE_ASYNC="true"
      ZSH_HIGHLIGHT_MAXLENGTH=512

      setopt AUTOCD AUTO_MENU AUTO_PARAM_SLASH COMPLETE_IN_WORD
      setopt NO_MENU_COMPLETE HASH_LIST_ALL ALWAYS_TO_END NOTIFY NOHUP MAILWARN
      setopt INTERACTIVE_COMMENTS NOBEEP APPEND_HISTORY SHARE_HISTORY INC_APPEND_HISTORY
      setopt EXTENDED_HISTORY HIST_IGNORE_ALL_DUPS HIST_IGNORE_SPACE HIST_NO_FUNCTIONS
      setopt HIST_EXPIRE_DUPS_FIRST HIST_SAVE_NO_DUPS HIST_REDUCE_BLANKS
      unsetopt FLOWCONTROL NOMATCH CORRECT EQUALS

      function git_current_branch() {
        git branch --show-current 2>/dev/null
      }

      function git_main_branch() {
        local branch
        for branch in main trunk mainline default master; do
          if git show-ref -q --verify refs/heads/$branch; then
            echo $branch
            return 0
          fi
        done
        echo master
      }

      function git_develop_branch() {
        local branch
        for branch in dev devel develop development; do
          if git show-ref -q --verify refs/heads/$branch; then
            echo $branch
            return 0
          fi
        done
        echo develop
      }

      function _smooth_fzf() {
        (
          local fname
          cd "''${XDG_CONFIG_HOME:-$HOME/.config}" || return
          fname="$(fzf)" || return
          "$EDITOR" "$fname"
        )
      }

      function _sudo_replace_buffer() {
        local old=$1 new=$2 space=''${2:+ }
        if [[ $CURSOR -le ''${#old} ]]; then
          BUFFER="''${new}''${space}''${BUFFER#$old }"
          CURSOR=''${#new}
        else
          LBUFFER="''${new}''${space}''${LBUFFER#$old }"
        fi
      }

      function _sudo_command_line() {
        [[ -z $BUFFER ]] && LBUFFER="$(fc -ln -1)"
        local WHITESPACE=""
        if [[ ''${LBUFFER:0:1} = " " ]]; then
          WHITESPACE=" "
          LBUFFER="''${LBUFFER:1}"
        fi
        {
          local EDITOR=''${SUDO_EDITOR:-''${VISUAL:-$EDITOR}}
          if [[ -z "$EDITOR" ]]; then
            case "$BUFFER" in
              sudo\ -e\ *) _sudo_replace_buffer "sudo -e" "" ;;
              sudo\ *) _sudo_replace_buffer "sudo" "" ;;
              *) LBUFFER="sudo $LBUFFER" ;;
            esac
            return
          fi
          local cmd="''${''${(Az)BUFFER}[1]}"
          local realcmd="''${''${(Az)aliases[$cmd]}[1]:-$cmd}"
          local editorcmd="''${''${(Az)EDITOR}[1]}"
          if [[ "$realcmd" = (\$EDITOR|$editorcmd|''${editorcmd:c}) \
            || "''${realcmd:c}" = ($editorcmd|''${editorcmd:c}) ]] \
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
          LBUFFER="''${WHITESPACE}''${LBUFFER}"
          zle redisplay
        }
      }

      function _vi_search_fix() {
        zle vi-cmd-mode
        zle .vi-history-search-backward
      }

      function toppy() {
        history | awk '{CMD[$2]++;count++;}END { for (a in CMD)print CMD[a] " " CMD[a]/count*100 "% " a;}' | grep -v "./" | column -c3 -s " " -t | sort -nr | nl | head -n 21
      }

      function git-svn() {
        if [[ -n "$1" && -n "$2" ]]; then
          echo "Starting clone/copy ..."
          repo=$(echo $1 | sed 's/\/$\|.git$//')
          svn export "$repo/trunk/$2"
        else
          echo "Use: git-svn <repository> <subdirectory>"
        fi
      }

      function _auto_eza_ls() {
        [[ -o interactive ]] && eza --color=auto --icons
      }

      add-zsh-hook chpwd _auto_eza_ls

      zle -N _vi_search_fix
      zle -N _sudo_command_line

      function zle-keymap-select {
        if [[ ''${KEYMAP} == vicmd ]] || [[ $1 = 'block' ]]; then
          echo -ne '\e[1 q'
        elif [[ ''${KEYMAP} == main ]] ||
          [[ ''${KEYMAP} == viins ]] ||
          [[ ''${KEYMAP} = "" ]] ||
          [[ $1 = 'beam' ]]; then
          echo -ne '\e[5 q'
        fi
      }
      zle -N zle-keymap-select

      function zle-line-init() {
        echo -ne '\e[5 q'
      }
      zle -N zle-line-init
      echo -ne '\e[5 q'

      bindkey -e
      bindkey '^[[H' beginning-of-line
      bindkey '^[[F' end-of-line
      bindkey -s '^K' 'ls^M'
      bindkey -s '^o' '_smooth_fzf^M'
      bindkey -M emacs '^B' _sudo_command_line
      bindkey -M vicmd '^B' _sudo_command_line
      bindkey -M viins '^B' _sudo_command_line
      bindkey -M viins '\e/' _vi_search_fix
      bindkey "^?" backward-delete-char
      bindkey "^H" backward-delete-char
      bindkey "^U" backward-kill-line

      zstyle ':completion:*:git-checkout:*' sort false
      zstyle ':completion:*:descriptions' format '[%d]'
      zstyle ':completion:*' list-colors ''${(s.:.)LS_COLORS}

      export LESS="--RAW-CONTROL-CHARS"
      export MANPAGER="less -s -M +Gg"
      export LESS_TERMCAP_mb=$'\e[1;32m'
      export LESS_TERMCAP_md=$'\e[1;32m'
      export LESS_TERMCAP_me=$'\e[0m'
      export LESS_TERMCAP_se=$'\e[0m'
      export LESS_TERMCAP_so=$'\e[01;33m'
      export LESS_TERMCAP_ue=$'\e[0m'
      export LESS_TERMCAP_us=$'\e[1;4;31m'

      if [[ -f "$HOME/.cargo/env" ]]; then
        . "$HOME/.cargo/env"
      fi
    '';
  };
}
