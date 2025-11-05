{
  pkgs,
  hostname,
  ...
}: let
  isLinux = hostname != "m3max" && hostname != "hackintosh";
in {
  programs.ghostty = {
    enable = true;
    package =
      if hostname == "home"
      then null
      else if isLinux
      then pkgs.ghostty
      else pkgs.ghostty-bin;
    # enableZshIntegration = true;
    # installBatSyntax = false;
    themes = {
      kanso = {
        background = "#090E13";
        foreground = "#c5c9c7";
        cursor-color = "#c5c9c7";
        palette = [
          "0=#090E13"
          "1=#c4746e"
          "2=#8a9a7b"
          "3=#c4b28a"
          "4=#8ba4b0"
          "5=#a292a3"
          "6=#8ea4a2"
          "7=#a4a7a4"
          "8=#5C6066"
          "9=#e46876"
          "10=#87a987"
          "11=#e6c384"
          "12=#7fb4ca"
          "13=#938aa9"
          "14=#7aa89f"
          "15=#c5c9c7"
        ];
        selection-background = "#22262D";
        selection-foreground = "#c5c9c7";
      };
    };
    settings = {
      theme = "kanso";
      font-size =
        if isLinux
        then 11.5
        else 15;
      window-decoration = true;
      font-family =
        if isLinux
        then "Recursive"
        else "RecMonoLinear Nerd Font Mono";
      background-opacity = 0.85;
      background-blur-radius = 20;
      macos-option-as-alt = true;
      macos-titlebar-style = "tabs";
      shell-integration = "detect";
      auto-update = "off";
      cursor-style = "bar";
      cursor-style-blink = false;
      adjust-cursor-thickness = "250%";
      shell-integration-features = "no-cursor";
      clipboard-read = "allow";
      clipboard-write = "allow";
      cursor-click-to-move = true;
      term = "xterm-256color";
      font-thicken = true;
      keybind = [
        "alt+i=toggle_quick_terminal"
      ];
      macos-icon = "xray";
    };
  };
}
##==default_keybindings (Darwin has Super instead of C):
# reset font              C-0
# smaller/bigger font     C-'-/+'
# write_scrollback_file   C-j
# new_window/close_surface/quit/close_window   C-S-n/w/q/ A-f4
# new_tab                 C-S-t
# split_right/down        C-S-o/e
# gotosplit left/right    S-Sup-</>
# goto split left/down/up/right <-..
# scroll top/bottom       S-home/end
# scroll up/down          S-pageup/pagedown
# semantic prompts?       S-C-pageup/pagedown
# inspector               S-C-i
# toggle fullscreen       C-Enter
# goto tab [1-9]          C-[1-9]

