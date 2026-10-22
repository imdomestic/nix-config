{lib, ...}: let
  palette = import ../../palettes/flat-white.nix;
  c = palette.colors;
in {
  programs.nixvim = {
    opts = {
      termguicolors = true;
      background = "dark";
    };
    colorschemes.mini-base16 = {
      enable = true;
      settings = {
        use_cterm = false;
        palette = {
          base00 = c.background;
          base01 = c.color0;
          base02 = c.selection_bg;
          base03 = c.color8;
          base04 = c.cursor;
          base05 = c.foreground;
          base06 = c.color7;
          base07 = c.color15;
          base08 = c.color1;
          base09 = c.color5;
          base0A = c.color6;
          base0B = c.color2;
          base0C = c.color6;
          base0D = c.color4;
          base0E = c.color3;
          base0F = c.color9;
        };
      };
    };
    globals = builtins.listToAttrs (lib.imap0 (i: value: {
        name = "terminal_color_${toString i}";
        inherit value;
      })
      palette.ansi);
    highlightOverride = {
      Normal = {
        fg = c.foreground;
        bg = c.background;
      };
      NormalFloat = {
        fg = c.foreground;
        bg = c.color0;
      };
      FloatBorder = {
        fg = c.color8;
        bg = c.color0;
      };
      Cursor = {
        fg = c.cursor_text;
        bg = c.cursor;
      };
      Visual = {
        fg = c.selection_fg;
        bg = c.selection_bg;
      };
      Search = {
        fg = c.background;
        bg = c.color3;
      };
      IncSearch = {
        fg = c.background;
        bg = c.color11;
        bold = true;
      };
      Comment = {
        fg = c.color8;
        italic = true;
      };
      Identifier.fg = c.foreground;
      "@variable".fg = c.foreground;
      LineNr.fg = c.color8;
      CursorLineNr = {
        fg = c.color3;
        bold = true;
      };
      Pmenu = {
        fg = c.foreground;
        bg = c.color0;
      };
      PmenuSel = {
        fg = c.selection_fg;
        bg = c.selection_bg;
      };
      StatusLine = {
        fg = c.foreground;
        bg = c.color0;
      };
      StatusLineNC = {
        fg = c.color8;
        bg = c.background;
      };
      DiagnosticError.fg = c.color1;
      DiagnosticWarn.fg = c.color3;
      DiagnosticInfo.fg = c.color4;
      DiagnosticHint.fg = c.color6;
      DiffAdd = {
        fg = c.color2;
        bg = c.color0;
      };
      DiffDelete = {
        fg = c.color1;
        bg = c.color0;
      };
      DiffChange = {bg = c.color0;};
      DiffText = {
        bg = c.selection_bg;
        bold = true;
      };
      GitSignsAdd.fg = c.color2;
      GitSignsChange.fg = c.color3;
      GitSignsDelete.fg = c.color1;
    };
    extraConfigLuaPost = lib.mkAfter ''vim.g.colors_name = "flat-white"'';
  };
}
