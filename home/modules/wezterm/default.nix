{
  lib,
  pkgs,
  ...
}: let
  lua = lib.generators.mkLuaInline;
  fontFallback = ''{ "Recursive", "FiraCode Nerd Font", "Apple Color Emoji", "azuki_font" }'';
in {
  programs.wezterm = {
    enable = pkgs.stdenv.isDarwin;
    enableZshIntegration = true;

    settings = {
      front_end = "WebGpu";
      window_decorations = "RESIZE";
      native_macos_fullscreen_mode = true;

      color_scheme = "Catppuccin Mocha";
      initial_cols = 96;
      initial_rows = 32;

      font = lua "wezterm.font_with_fallback(${fontFallback})";
      font_rules = [
        {
          italic = true;
          font = lua ''
            wezterm.font_with_fallback(
              ${fontFallback},
              { italic = true, weight = "Regular" }
            )
          '';
        }
        {
          italic = false;
          font = lua ''
            wezterm.font_with_fallback(
              ${fontFallback},
              { italic = false, weight = "Regular" }
            )
          '';
        }
        {
          intensity = "Bold";
          font = lua ''
            wezterm.font_with_fallback(
              ${fontFallback},
              { bold = true }
            )
          '';
        }
      ];
      warn_about_missing_glyphs = false;
      font_size = 16;
      line_height = 1.0;

      default_cursor_style = "BlinkingUnderline";
      cursor_blink_rate = 0;

      disable_default_key_bindings = true;
      keys = [
        {
          key = "\\";
          mods = "CTRL|ALT";
          action = lua ''
            wezterm.action({
              SplitHorizontal = { domain = "CurrentPaneDomain" },
            })
          '';
        }
        {
          key = "\\";
          mods = "CTRL";
          action = lua ''
            wezterm.action({
              SplitVertical = { domain = "CurrentPaneDomain" },
            })
          '';
        }
        {
          key = "q";
          mods = "CTRL";
          action = lua ''
            wezterm.action({
              CloseCurrentPane = { confirm = false },
            })
          '';
        }
        {
          key = "h";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ ActivatePaneDirection = "Left" })
          '';
        }
        {
          key = "l";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ ActivatePaneDirection = "Right" })
          '';
        }
        {
          key = "k";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ ActivatePaneDirection = "Up" })
          '';
        }
        {
          key = "j";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ ActivatePaneDirection = "Down" })
          '';
        }
        {
          key = "h";
          mods = "CTRL|SHIFT|ALT";
          action = lua ''
            wezterm.action({ AdjustPaneSize = { "Left", 1 } })
          '';
        }
        {
          key = "l";
          mods = "CTRL|SHIFT|ALT";
          action = lua ''
            wezterm.action({ AdjustPaneSize = { "Right", 1 } })
          '';
        }
        {
          key = "k";
          mods = "CTRL|SHIFT|ALT";
          action = lua ''
            wezterm.action({ AdjustPaneSize = { "Up", 1 } })
          '';
        }
        {
          key = "j";
          mods = "CTRL|SHIFT|ALT";
          action = lua ''
            wezterm.action({ AdjustPaneSize = { "Down", 1 } })
          '';
        }
        {
          key = "t";
          mods = "CTRL";
          action = lua ''
            wezterm.action({ SpawnTab = "CurrentPaneDomain" })
          '';
        }
        {
          key = "w";
          mods = "CTRL";
          action = lua ''
            wezterm.action({
              CloseCurrentTab = { confirm = false },
            })
          '';
        }
        {
          key = "Tab";
          mods = "CTRL";
          action = lua ''
            wezterm.action({ ActivateTabRelative = 1 })
          '';
        }
        {
          key = "Tab";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ ActivateTabRelative = -1 })
          '';
        }
        {
          key = "x";
          mods = "CTRL";
          action = "ActivateCopyMode";
        }
        {
          key = "v";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({ PasteFrom = "Clipboard" })
          '';
        }
        {
          key = "c";
          mods = "CTRL|SHIFT";
          action = lua ''
            wezterm.action({
              CopyTo = "ClipboardAndPrimarySelection",
            })
          '';
        }
        {
          key = "n";
          mods = "CTRL|SHIFT";
          action = lua "wezterm.action.ToggleFullScreen";
        }
      ];

      bold_brightens_ansi_colors = true;
      window_padding = {
        left = 5;
        right = 5;
        top = 5;
        bottom = 5;
      };

      enable_tab_bar = true;
      hide_tab_bar_if_only_one_tab = true;
      show_tab_index_in_tab_bar = false;
      use_fancy_tab_bar = true;
      tab_bar_at_bottom = true;

      automatically_reload_config = true;
      inactive_pane_hsb = {
        saturation = 1.0;
        brightness = 1.0;
      };
      window_background_opacity = 0.85;
      macos_window_background_blur = 40;
      window_close_confirmation = "NeverPrompt";
      window_frame = {
        active_titlebar_bg = "#45475a";
        font = lua ''
          wezterm.font_with_fallback(
            ${fontFallback},
            { bold = true }
          )
        '';
      };
    };
  };
}
