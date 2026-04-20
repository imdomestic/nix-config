{pkgs, ...}: {
  programs.tmux = {
    enable = true;
    terminal = "tmux-256color";
    mouse = true;
    prefix = "C-a";
    baseIndex = 1;
    keyMode = "vi";

    plugins = with pkgs.tmuxPlugins; [
      sensible
      {
        plugin = resurrect;
        extraConfig = ''
          set -g @resurrect-capture-pane-contents 'on'
          set -g @resurrect-pane-contents-area 'full'
        '';
      }
      {
        plugin = continuum;
        extraConfig = ''
          set -g @continuum-restore 'on'
          set -g @continuum-save-interval '15'
        '';
      }
      vim-tmux-navigator
      yank
      catppuccin
    ];

    extraConfig = ''
      # Keep terminal features and low-latency key handling.
      set-option -ga terminal-overrides ",*256col*:Tc"
      set -ga terminal-overrides ',*:Ss=\E[%p1%d q:Se=\E[6 q'
      set -sg escape-time 0
      set -g history-limit 100000

      setw -g pane-base-index 1

      unbind '"'
      unbind %
      bind | split-window -h
      bind - split-window -v
      bind % split-window -h
      bind '"' split-window -v

      bind -n C-h select-pane -L
      bind -n C-j select-pane -D
      bind -n C-k select-pane -U
      bind -n C-l select-pane -R

      bind r source-file ~/.tmux.conf \; display "Reloaded!"

      set -g status-position top
      set -g status-interval 1
      set -g status-style bg=#1a1b26,fg=#c0caf5

      setw -g window-status-style fg=#565f89,bg=#1a1b26
      setw -g window-status-current-style fg=#1a1b26,bg=#7aa2f7,bold
      setw -g window-status-format " #[fg=#565f89]#I:#W "
      setw -g window-status-current-format " #[fg=#1a1b26,bg=#7aa2f7,bold]#I:#W "

      set -g status-left-length 60
      set -g status-left "#[fg=#7aa2f7,bold] #S #[fg=#565f89]|#[fg=#89b4fa] #(whoami)@#H "

      set -g status-right-length 120
      set -g status-right "#[fg=#9aa5ce] #{pane_current_path} #[fg=#565f89]|#[fg=#bb9af7] %Y-%m-%d %H:%M:%S "

      set -g pane-border-style fg=#2f3549
      set -g pane-active-border-style fg=#ff9e64
      set -g window-style bg=#0f1117
      set -g window-active-style bg=#1a1b26
    '';
  };
}
