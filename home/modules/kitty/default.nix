{
  pkgs,
  system,
  ...
}: let
  kanso = {
    background = "#121212";
    foreground = "#c6c8d1";
    selection_background = "#393B42";
    selection_foreground = "#C5C9C7";
    url_color = "#72A7BC";
    cursor = "#C5C9C7";
    cursor_text_color = "#090E13";

    active_tab_background = "#090E13";
    active_tab_foreground = "#8ba4b0";
    inactive_tab_background = "#090E13";
    inactive_tab_foreground = "#A4A7A4";
    tab_bar_background = "#131313";

    color0 = "#0d0c0c";
    color1 = "#c4746e";
    color2 = "#8a9a7b";
    color3 = "#c4b28a";
    color4 = "#8ba4b0";
    color5 = "#a292a3";
    color6 = "#8ea4a2";
    color7 = "#C8C093";

    color8 = "#A4A7A4";
    color9 = "#E46876";
    color10 = "#87a987";
    color11 = "#E6C384";
    color12 = "#7FB4CA";
    color13 = "#938AA9";
    color14 = "#7AA89F";
    color15 = "#C5C9C7";

    color16 = "#b6927b";
    color17 = "#b98d7b";
  };
  lib = pkgs.lib;
  isLinux = lib.hasInfix "linux" system;
in {
  programs.kitty = {
    enable = true;
    font.name =
      if isLinux
      then "Recursive"
      else "RecMonoLinear Nerd Font Mono";
    extraConfig =
      if isLinux
      then ''
        # kitty-scrollback.nvim Kitten alias
        action_alias kitty_scrollback_nvim kitten /home/hank/.local/share/nvim/lazy/kitty-scrollback.nvim/python/kitty_scrollback_nvim.py
        # Browse scrollback buffer in nvim
        map kitty_mod+h kitty_scrollback_nvim
        # Browse output of the last shell command in nvim
        map kitty_mod+g kitty_scrollback_nvim --config ksb_builtin_last_cmd_output
        # Show clicked command output in nvim
        mouse_map ctrl+shift+right press ungrabbed combine : mouse_select_command_output : kitty_scrollback_nvim --config ksb_builtin_last_visited_cmd_output
      ''
      else ''
        # kitty-scrollback.nvim Kitten alias
        action_alias kitty_scrollback_nvim kitten /Users/hank/.local/share/nvim/lazy/kitty-scrollback.nvim/python/kitty_scrollback_nvim.py
        # Browse scrollback buffer in nvim
        map kitty_mod+h kitty_scrollback_nvim
        # Browse output of the last shell command in nvim
        map kitty_mod+g kitty_scrollback_nvim --config ksb_builtin_last_cmd_output
        # Show clicked command output in nvim
        mouse_map ctrl+shift+right press ungrabbed combine : mouse_select_command_output : kitty_scrollback_nvim --config ksb_builtin_last_visited_cmd_output
      '';
    settings =
      {
        font_size =
          if isLinux
          then 11.5
          else 15;
        cursor_shape = "beam";
        cursor_shape_unfocused = "hollow";
        cursor_trail = 1;
        cursor_blink_interval = 0;
        background_opacity = 0.85;
        background_blur =
          if isLinux
          then 0
          else 20;
        hide_window_decorations = true;
        tab_bar_min_tabs = 1;
        tab_bar_edge = "bottom";
        tab_bar_style = "powerline";
        tab_powerline_style = "slanted";
        tab_title_template = "{title}{' :{}:'.format(num_windows) if num_windows > 1 else ''}";
        wayland_titlebar_color = "system";
        macos_titlebar_color = "system";
        macos_option_as_alt = true;
        sync_to_monitor = true;
        allow_remote_control = true;
        listen_on = "unix:/tmp/kitty";
        shell_integration = "enabled";
      }
      // kanso;
    # // noir;
  };
}
# noir = {
#   background = "#121212";
#   foreground = "#c6c8d1";
#
#   selection_background = "#1e2132";
#   selection_foreground = "#c6c8d1";
#
#   cursor = "#d2d4de";
#
#   # black
#   color0 = "#121212";
#   color8 = "#212121";
#
#   # red
#   color1 = "#bf616a";
#   color9 = "#bf616a";
#
#   # green
#   color2 = "#a3be8c";
#   color10 = "#a3be8c";
#
#   # yellow/orange
#   color3 = "#ebcb8b";
#   color11 = "#ebcb8b";
#
#   # blue
#   color4 = "#8fbcbb";
#   color12 = "#8fbcbb";
#
#   # magenta/purple
#   color5 = "#a093c7";
#   color13 = "#ada0d3";
#
#   # cyan
#   color6 = "#47eae0";
#   color14 = "#47eae0";
#
#   # white
#   color7 = "#f5f5f5";
#   color15 = "#ffffff";
#
#   # tab bar
#   active_tab_foreground = "#131313";
#   active_tab_background = "#a3be8c";
#   inactive_tab_foreground = "#d5d5d5";
#   inactive_tab_background = "#323232";
#   tab_bar_background = "#131313";
# };
#

