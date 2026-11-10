let
  theme = "evergarden-winter-green";
in {
  programs.helix = {
    enable = true;
    settings.theme = theme;

    # 与 Hank 的 nixvim / lazygit 同用 Evergarden Winter / Green。高亮角色抄自
    # evergardentheme/helix@53cad3aa2623faf837bb19cc81dfd5c8b2772b10 的 helix.tera，
    # 颜色取共用调色板（与上游 winter 逐值相同）。
    themes.${theme} = {
      # ------------------- #
      # Syntax Highlighting #
      # ------------------- #
      attribute = "cherry";
      type = {
        fg = "yellow";
        modifiers = ["italic"];
      };
      constructor = "green";
      constant = "pink";
      string = "lime";
      "string.regexp" = "yellow";
      "string.special" = "aqua";
      "string.special.path" = "blue";
      "string.special.url" = "blue";
      comment = {
        fg = "overlay2";
        modifiers = ["italic"];
      };
      variable = "text";
      "variable.builtin" = "pink";
      "variable.other.member" = "skye";
      label = {
        fg = "red";
        modifiers = ["italic"];
      };
      punctuation = "overlay1";
      "punctuation.special" = "aqua";
      keyword = {
        fg = "red";
        modifiers = ["italic"];
      };
      "keyword.operator" = "orange";
      "keyword.directive" = "cherry";
      operator = "subtext0";
      function = "green";
      "function.builtin" = "pink";
      "function.macro" = "aqua";
      tag = "skye";
      namespace = "snow";
      special = "lime";
      markup = "text";
      "markup.heading" = "red";
      "markup.heading.1" = "red";
      "markup.heading.2" = "orange";
      "markup.heading.3" = "yellow";
      "markup.heading.4" = "green";
      "markup.heading.5" = "aqua";
      "markup.heading.6" = "blue";
      "markup.list" = "overlay1";
      "markup.list.checked" = "green";
      "markup.list.unchecked" = "overlay1";
      "markup.bold" = {
        fg = "aqua";
        modifiers = ["bold"];
      };
      "markup.italic" = {
        fg = "aqua";
        modifiers = ["italic"];
      };
      "markup.link" = "blue";
      "markup.link.label" = {
        fg = "blue";
        modifiers = ["italic"];
      };
      "markup.quote" = {
        fg = "overlay2";
        modifiers = ["italic"];
      };
      "markup.raw" = "overlay1";
      "diff.plus" = "green";
      "diff.minus" = "red";
      "diff.delta" = "aqua";

      # -------------- #
      # User Interface #
      # -------------- #
      "ui.background" = {
        fg = "text";
        bg = "base";
      };
      "ui.background.separator".bg = "surface0";
      "ui.cursor" = {
        fg = "base";
        bg = "secondary_cursor";
      };
      "ui.cursor.primary" = {
        fg = "base";
        bg = "text";
      };
      "ui.cursor.match" = {
        fg = "orange";
        modifiers = ["bold"];
      };
      "ui.cursor.primary.normal" = {
        fg = "base";
        bg = "aqua";
      };
      "ui.cursor.primary.insert" = {
        fg = "base";
        bg = "text";
      };
      "ui.cursor.primary.select" = {
        fg = "base";
        bg = "pink";
      };
      "ui.linenr" = "surface2";
      "ui.statusline" = {
        fg = "overlay2";
        bg = "mantle";
      };
      "ui.statusline.normal" = {
        fg = "base";
        bg = "aqua";
        modifiers = ["bold"];
      };
      "ui.statusline.insert" = {
        fg = "base";
        bg = "text";
        modifiers = ["bold"];
      };
      "ui.statusline.select" = {
        fg = "base";
        bg = "pink";
        modifiers = ["bold"];
      };
      "ui.bufferline" = {
        fg = "subtext0";
        bg = "mantle";
      };
      "ui.bufferline.active" = {
        fg = "text";
        bg = "base";
        underline = {
          color = "text";
          style = "line";
        };
      };
      "ui.bufferline.background".bg = "crust";
      "ui.help" = {
        fg = "overlay2";
        bg = "surface0";
      };
      "ui.popup" = {
        fg = "text";
        bg = "mantle";
      };
      "ui.popup.header".fg = "subtext0";
      "ui.window" = "surface0";
      "ui.text" = "text";
      "ui.text.focus" = {
        fg = "text";
        bg = "surface0";
        modifiers = ["bold"];
      };
      "ui.text.inactive" = "overlay1";
      "ui.text.directory" = "blue";
      "ui.virtual" = "overlay0";
      "ui.virtual.ruler".bg = "surface0";
      "ui.virtual.indent-guide" = "surface0";
      "ui.virtual.inlay-hint" = {
        fg = "surface1";
        bg = "mantle";
      };
      "ui.virtual.jump-label" = {
        fg = "accent";
        modifiers = ["bold"];
      };
      "ui.menu" = {
        fg = "text";
        bg = "mantle";
      };
      "ui.menu.selected" = {
        fg = "text";
        bg = "surface1";
      };
      "ui.menu.scroll" = "accent";
      "ui.selection" = {
        fg = "text";
        bg = "surface1";
      };
      "ui.highlight" = {
        bg = "surface1";
        modifiers = ["bold"];
      };
      "ui.cursorline".bg = "surface0";
      "ui.cursorcolumn".bg = "surface0";
      warning = "yellow";
      error = "red";
      info = "aqua";
      hint = "skye";
      "diagnostic.hint" = "skye";
      "diagnostic.info" = "aqua";
      "diagnostic.warning" = "yellow";
      "diagnostic.error" = "red";
      "diagnostic.unnecessary" = {
        fg = "overlay0";
        modifiers = ["italic"];
      };
      "diagnostic.deprecated" = {
        fg = "overlay0";
        modifiers = ["crossed_out"];
      };

      palette = let
        inherit (import ../palettes/evergarden-winter.nix) colors roles;
      in
        removeAttrs colors ["diffAddBg" "diffDelBg" "diffAddWord" "diffDelWord"]
        // {
          inherit (roles) accent;
          # 上游模板算的 text 70% / base 30% 混色。
          secondary_cursor = "#b7baaf";
        };
    };
  };
}
