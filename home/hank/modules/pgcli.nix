let
  inherit (import ./palettes/evergarden-winter.nix) colors;
  # ConfigObj reads an unquoted `#` as the start of a comment.
  quote = style: "'${style}'";
in {
  # Evergarden Winter / Green, like Hank's nixvim, helix and lazygit. Upstream
  # has no pgcli port; the roles follow evergardentheme/nvim (hl/editor.lua,
  # hl/treesitter.lua) with the style overrides nixvim sets: keywords and types
  # upright, comments italic.
  programs.pgcli = {
    enable = true;
    settings = {
      # A colourless base: a token not listed below keeps the terminal's
      # foreground instead of picking up another theme's colour.
      main.syntax_style = "bw";

      colors = builtins.mapAttrs (_: quote) (with colors; {
        # The SQL being typed. pgcli has no name for these classes (nor for
        # scrollbar.* below): they reach the prompt, and each logs "Unhandled
        # style / class name" to ~/.config/pgcli/log on every start.
        "pygments.keyword" = "${red} nobold";
        "pygments.name.builtin" = yellow; # data types
        "pygments.literal.string" = "${lime} noitalic";
        "pygments.literal.number" = pink;
        "pygments.operator" = subtext0;
        "pygments.punctuation" = overlay1;
        "pygments.comment" = "${overlay2} italic";

        # Pmenu, PmenuSel, PmenuKind, PmenuSbar, PmenuThumb. The classes pgcli
        # does know are also parsed as a Pygments style, which rejects
        # prompt_toolkit's `noreverse` (pgcli then dies on start): `noinherit`
        # is what drops the default `reverse` of the current completion and of
        # the selection.
        "completion-menu.completion" = "bg:${mantle} ${text}";
        "completion-menu.completion.current" = "noinherit bg:${surface1} ${text} bold";
        "completion-menu.meta.completion" = "bg:${mantle} ${subtext0}";
        "completion-menu.meta.completion.current" = "bg:${surface1} ${subtext0}";
        "completion-menu.multi-column-meta" = "bg:${surface1} ${subtext0}";
        "scrollbar.background" = "bg:${surface1}";
        "scrollbar.button" = "bg:${overlay0}";
        # pgcli's default teal, which otherwise repaints the cell at each end
        # of the thumb.
        scrollbar = "";

        # Visual, Search, CurSearch
        selected = "noinherit bg:${surface1} ${text}";
        search = "bg:${surface1} ${subtext1} bold";
        "search.current" = "bg:${snow} ${crust} bold";

        # StatusLine, StatusLineNC
        bottom-toolbar = "bg:${mantle} ${subtext0}";
        "bottom-toolbar.off" = "bg:${mantle} ${overlay1}";
        "bottom-toolbar.on" = "bg:${mantle} ${text}";
        "bottom-toolbar.transaction.valid" = "bg:${mantle} ${green} bold";
        "bottom-toolbar.transaction.failed" = "bg:${mantle} ${red} bold";

        "output.header" = "${green} bold";
        "output.null" = overlay1;
      });
    };
  };

  # prompt_toolkit draws in 256 colours whatever COLORTERM says, which turns the
  # palette's tinted greys neutral and its text yellow. Same fact as
  # SNACKS_GHOSTTY in ../default.nix: Hank's terminal is ghostty, over ssh too.
  home.sessionVariables.PROMPT_TOOLKIT_COLOR_DEPTH = "DEPTH_24_BIT";
}
