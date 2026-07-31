{
  config,
  pkgs,
  ...
}: {
  imports = [
    ../../modules/nixvim/kenneth.nix
    ../../modules/wezterm
  ];

  home = {
    packages = [
      pkgs.gnumake
      pkgs.nodejs
      pkgs.pnpm
      pkgs.subversion
    ];

    sessionPath = [
      "$HOME/.local/bin"
    ];

    sessionVariables = {
      EDITOR = "nvim";
      LESS = "--RAW-CONTROL-CHARS";
      LESS_TERMCAP_mb = builtins.fromJSON ''"\u001b[1;32m"'';
      LESS_TERMCAP_md = builtins.fromJSON ''"\u001b[1;32m"'';
      LESS_TERMCAP_me = builtins.fromJSON ''"\u001b[0m"'';
      LESS_TERMCAP_se = builtins.fromJSON ''"\u001b[0m"'';
      LESS_TERMCAP_so = builtins.fromJSON ''"\u001b[01;33m"'';
      LESS_TERMCAP_ue = builtins.fromJSON ''"\u001b[0m"'';
      LESS_TERMCAP_us = builtins.fromJSON ''"\u001b[1;4;31m"'';
      MANPAGER = "less -s -M +Gg";
      VISUAL = "nvim";
    };
  };

  xdg.enable = true;

  programs.git.enable = true;

  programs.lazygit = {
    enable = true;
    enableZshIntegration = false;
  };

  programs.starship = {
    enable = true;
    enableZshIntegration = true;
    settings = {
      python.disabled = true;
    };
  };

  programs.btop = {
    enable = true;
    settings = {
      color_theme = "Default";
      graph_symbol = "braille";
      shown_boxes = "cpu mem net proc";
      update_ms = 500;
    };
  };

  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    clock24 = true;
    keyMode = "vi";
    baseIndex = 1;
    escapeTime = 0;
    historyLimit = 50000;
    plugins = with pkgs.tmuxPlugins; [dotbar];
    extraConfig = ''
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -g allow-passthrough on
      set -g set-clipboard on
      set-option -g renumber-windows on
    '';
  };

  programs.zsh = {
    enable = true;
    dotDir = "${config.xdg.configHome}/zsh";
    autocd = true;
    defaultKeymap = "emacs";

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
      saveNoDups = true;
      share = true;
      size = 10000;
    };

    historySubstringSearch.enable = true;

    localVariables = {
      background = "#1E1E2E";
      foreground = "#CDD6F4";
      color8 = "#585B70";
      ZSH_AUTOSUGGEST_USE_ASYNC = "true";
      ZSH_HIGHLIGHT_MAXLENGTH = 512;
    };

    setOptions = [
      "AUTO_MENU"
      "AUTO_PARAM_SLASH"
      "COMPLETE_IN_WORD"
      "NO_MENU_COMPLETE"
      "HASH_LIST_ALL"
      "ALWAYS_TO_END"
      "NOTIFY"
      "NOHUP"
      "MAILWARN"
      "INTERACTIVE_COMMENTS"
      "NO_BEEP"
      "HIST_NO_FUNCTIONS"
      "HIST_REDUCE_BLANKS"
      "NO_FLOW_CONTROL"
      "NO_NOMATCH"
      "NO_CORRECT"
      "NO_EQUALS"
    ];

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

      if [[ -f "$HOME/.cargo/env" ]]; then
        . "$HOME/.cargo/env"
      fi
    '';
  };
}
