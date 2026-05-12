{
  pkgs,
  ...
}: {
  services.paneru = {
    enable = true;
    settings = {
      options = {
        focus_follows_mouse = false;
        mouse_follows_focus = true;
        auto_center = false;
        animation_speed = 12.0;
        preset_column_widths = [0.33333 0.5 0.66667];
        window_resize_cycle = true;
        mouse_resize_modifier = "cmd + shift";
      };

      # 屏幕边缘留白:4 + 窗口自带 padding:4 → 窗口与屏幕边缘 8px;
      # 相邻窗口各贡献 4 → 窗口之间 8px。
      padding = {
        top = 4;
        bottom = 4;
        left = 4;
        right = 4;
      };

      swipe = {
        sensitivity = 0.35;
        deceleration = 4.0;
        continuous = true;
        gesture = {
          fingers_count = 4;
          direction = "Natural";
        };
        scroll = {
          modifier = "alt";
          vertical_modifier = "shift";
        };
      };

      decorations.inactive.dim = {
        # opacity = -0.15;
        # opacity_night = -0.25;
        opacity = 0;
        opacity_night = 0;
      };

      bindings = {
        # ---- Focus (alt + h/j/k/l) ----
        "window_focus_west" = "alt - h";
        "window_focus_east" = "alt - l";
        "window_focus_south" = "alt - j";
        "window_focus_north" = "alt - k";
        "window_focus_first" = "alt - n";
        "window_focus_last" = "alt - m";

        # ---- Move / swap (alt + shift + h/j/k/l) ----
        "window_swap_west" = "alt + shift - h";
        "window_swap_east" = "alt + shift - l";
        "window_swap_south" = "alt + shift - j";
        "window_swap_north" = "alt + shift - k";
        "window_swap_first" = "alt + shift - n";
        "window_swap_last" = "alt + shift - m";

        # ---- Sizing (matches niri Mod+R / Mod+Shift+R / Mod+F / Mod+C) ----
        "window_resize" = "alt - r";
        "window_shrink" = "alt + shift - r";
        "window_fullwidth" = "alt - f";
        "window_center" = "alt - c";
        "window_snap" = "alt - s";

        # ---- Stacking (matches niri Mod+[ / Mod+] consume-or-expel) ----
        "window_stack" = "alt - leftbracket";
        "window_unstack" = "alt - rightbracket";
        "window_equalize" = "alt - e";

        # ---- Floating toggle (matches niri & aerospace alt+shift+space) ----
        "window_manage" = "alt + shift - space";

        # ---- Cross-display (matches niri Mod+Ctrl+L direction-ish) ----
        "window_nextdisplay" = "alt + ctrl - l";
        "window_nextdisplaysend" = "alt + shift + ctrl - l";
        "mouse_nextdisplay" = "alt + ctrl - m";

        # ---- Virtual workspaces (matches niri Mod+U / Mod+I) ----
        "window_virtual_south" = "alt - i";
        "window_virtual_north" = "alt - u";
        "window_virtualmove_south" = "alt + shift - i";
        "window_virtualmove_north" = "alt + shift - u";

        # ---- Quit ----
        "quit" = "ctrl + alt - q";
      };

      # Window rules
      windows = {
        # 全局默认:给每个窗口加 4px 内边距,相邻窗口累加 → 8px 窗口间隙
        default = {
          title = ".*";
          horizontal_padding = 4;
          vertical_padding = 4;
        };
      };
    };
  };
}
