{pkgs, ...}: let
  c = (import ../palettes/flat-white.nix).colors;
in {
  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    prefix = "C-a";
    baseIndex = 1;
    keyMode = "vi";
    escapeTime = 0;
    historyLimit = 100000;

    plugins = with pkgs.tmuxPlugins; [
      sensible
      {
        plugin = resurrect;
        extraConfig = ''
          set -g @resurrect-capture-pane-contents 'on'
          set -g @resurrect-pane-contents-area 'full'
        '';
      }
      yank
      {
        plugin = continuum;
        extraConfig = ''
          set -g @continuum-restore 'on'
          set -g @continuum-save-interval '15'
          # continuum 加载时会向 status-right 添加自动保存命令。
          set -g status-right "#[fg=${c.color4}] #{pane_current_path} #[fg=${c.color8}]|#[fg=${c.color3}] %Y-%m-%d %H:%M:%S "
        '';
      }
    ];

    extraConfig = ''
      # Keep terminal features and low-latency key handling.
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -ga terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[6 q'
      set -g set-clipboard on
      set -ga terminal-overrides ',*:Ms=\E]52;%p1%s;%p2%s\007'
      set -g allow-passthrough on
      set -s extended-keys on
      set -s extended-keys-format csi-u
      set -as terminal-features 'xterm*:extkeys'

      setw -g pane-base-index 1

      unbind '"'
      unbind %
      bind | split-window -h
      bind - split-window -v
      bind % split-window -h
      bind '"' split-window -v

      unbind -n C-h
      unbind -n C-j
      unbind -n C-k
      unbind -n C-l
      bind h select-pane -L
      bind j select-pane -D
      bind k select-pane -U
      bind l select-pane -R

      bind r source-file ~/.config/tmux/tmux.conf \; display "Reloaded!"

      set -g status-position top
      set -g status-interval 1
      set -g status-style bg=${c.background},fg=${c.foreground}

      setw -g window-status-style fg=${c.color8},bg=${c.background}
      setw -g window-status-current-style fg=${c.background},bg=${c.color4},bold
      setw -g window-status-format " #[fg=${c.color8}]#I:#W "
      setw -g window-status-current-format " #[fg=${c.background},bg=${c.color4},bold]#I:#W "
      setw -g window-status-activity-style fg=${c.color3}
      setw -g window-status-bell-style fg=${c.color1}

      set -g status-left-length 60
      set -g status-left "#[fg=${c.color4},bold] #S #[fg=${c.color8}]|#[fg=${c.color6}] #(whoami)@#H "

      set -g status-right-length 120

      set -g pane-border-style fg=${c.selection_bg}
      set -g pane-active-border-style fg=${c.color3}
      set -g window-style bg=${c.background}
      set -g window-active-style bg=${c.background}
      set -g message-style bg=${c.color0},fg=${c.foreground}
      set -g message-command-style bg=${c.color0},fg=${c.color3}
      setw -g mode-style bg=${c.selection_bg},fg=${c.selection_fg}
      setw -g clock-mode-colour ${c.color4}
      set -g display-panes-colour ${c.color8}
      set -g display-panes-active-colour ${c.color3}
    '';
  };
}
