{
  lib,
  pkgs,
  ...
}: {
  # Explicit Homebrew formulae from Alex. bat, eza, neovim, node and ripgrep
  # are already supplied by Kenneth's existing Home Manager profiles.
  home.packages = with pkgs; [
    # Homebrew's 9.x innovation series is not packaged on this pinned branch;
    # use the maintained MySQL 8.4 LTS server and client instead.
    mysql84
    nginx
    php
    python312
    qemu
  ];

  home.sessionVariables = {
    BROWSER = "firefox";
    CONDA_AUTO_ACTIVATE_BASE = "false";
    TERMINAL = "wezterm";
  };

  # OrbStack owns this generated integration fragment. Keep only the minimal
  # conditional hook here instead of copying its dotfile into the repository.
  programs.zsh.profileExtra = lib.mkAfter ''
    if [[ -r "$HOME/.orbstack/shell/init.zsh" ]]; then
      source "$HOME/.orbstack/shell/init.zsh"
    fi
  '';

  # The Conda installation is outside Nix, but its generated shell files used
  # to hard-code /Users/ztymac. Discover the existing installation relative to
  # the renamed home instead. `channels: defaults` is Conda's default, while
  # auto activation is represented by CONDA_AUTO_ACTIVATE_BASE above.
  programs.zsh.initContent = lib.mkAfter ''
    for conda_root in "$HOME/anaconda3" /opt/anaconda3 /opt/homebrew/anaconda3; do
      if [[ -x "$conda_root/bin/conda" ]]; then
        eval "$("$conda_root/bin/conda" shell.zsh hook 2>/dev/null)"
        break
      fi
    done
    unset conda_root
  '';

  programs.claude-code = {
    enable = true;
    # Claude is currently installed by its own version manager under
    # ~/.local/bin; Home Manager only owns the reusable settings.
    package = null;
    settings.theme = "dark";
  };

  # Kenneth's current Ghostty configuration, expressed through Home Manager's
  # native settings option. The application itself remains independently
  # installed; this module owns only its reusable configuration.
  programs.ghostty.settings = lib.mkForce {
    theme = "Catppuccin Mocha";
    background-opacity = 0.85;
    background-blur = 40;
    window-padding-x = 5;
    window-padding-y = 5;
    window-width = 96;
    window-height = 32;
    window-decoration = "auto";
    macos-titlebar-style = "tabs";
    macos-non-native-fullscreen = false;
    unfocused-split-opacity = 1;
    bold-color = "bright";

    font-family = [
      "Recursive"
      "PingFang SC"
      "Fira Code"
      "Apple Color Emoji"
    ];
    font-size = 16;
    font-thicken = true;
    window-title-font-family = "Recursive";

    cursor-style = "underline";
    cursor-style-blink = false;
    shell-integration = "detect";
    shell-integration-features = "no-cursor";
    cursor-click-to-move = true;

    clipboard-read = "allow";
    clipboard-write = "allow";
    term = "xterm-256color";
    macos-option-as-alt = true;
    confirm-close-surface = false;
    auto-update = "off";
    keybind = ["alt+i=toggle_quick_terminal"];
  };
}
