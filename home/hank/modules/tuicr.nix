{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  tuicr = inputs.llm-agents.packages.${pkgs.stdenv.hostPlatform.system}.tuicr;
  toml = pkgs.formats.toml {};

  # tuicr 0.28.0's agent skill has no Rex wrapper; upstream main added it after
  # that release (agavra/tuicr#821, #829). Any later release ships it, and then
  # the packaged copy takes over on its own.
  skill =
    if lib.versionAtLeast tuicr.version "0.28.1"
    then "${tuicr}/share/skills/tuicr/tuicr"
    else
      pkgs.runCommand "tuicr-skill" {buildInputs = [pkgs.bash];} ''
        cp -r ${pkgs.fetchFromGitHub {
          owner = "agavra";
          repo = "tuicr";
          rev = "928a536e5c939ed3c3217703c06f140ee5d9a258";
          sparseCheckout = ["skills/tuicr"];
          hash = "sha256-MtdigFT6ntQ+5mTgmblRwkSOxO9UkH13zYG3JpgaMcI=";
        }}/skills/tuicr $out
        chmod -R u+w $out
        patchShebangs --host $out
      '';

  # Evergarden Winter / Green, like Hank's nixvim, helix and lazygit; the diff
  # roles follow the opencode theme (modules/opencode/default.nix).
  evergardenWinter = with (import ./palettes/evergarden-winter.nix).colors; {
    panel_bg = base;
    bg_highlight = surface1;
    fg_primary = text;
    fg_secondary = subtext0;
    fg_dim = overlay1;

    diff_add = green;
    diff_add_bg = diffAddBg;
    diff_del = red;
    diff_del_bg = diffDelBg;
    diff_context = subtext0;
    diff_hunk_header = overlay1;
    expanded_context_fg = overlay1;
    syntax_add_bg = diffAddBg;
    syntax_del_bg = diffDelBg;
    # The same upstream bat theme Codex uses (modules/codex/default.nix).
    syntax_theme = "${pkgs.fetchurl {
      url = "https://raw.githubusercontent.com/evergardentheme/bat/aa5b92e927d1169673050f4f444496590e053487/themes/evergarden-winter.tmTheme";
      hash = "sha256-jZ6Rc6ScIffy73FQJn8FYqJG5pS/6plk4oqJModbxKw=";
    }}";

    file_added = green;
    file_modified = yellow;
    file_deleted = red;
    file_renamed = purple;
    reviewed = green;
    pending = yellow;

    comment_note = blue;
    comment_suggestion = skye;
    comment_issue = red;
    comment_praise = green;

    border_focused = green;
    border_unfocused = surface2;
    status_bar_bg = mantle;
    cursor_color = orange;
    cursor_line_bg = surface0;
    branch_name = purple;
    help_indicator = overlay1;

    message_info_fg = base;
    message_info_bg = blue;
    message_warning_fg = base;
    message_warning_bg = yellow;
    message_error_fg = base;
    message_error_bg = red;
    update_badge_fg = base;
    update_badge_bg = yellow;
    mode_fg = base;
    mode_bg = green;
  };
in {
  home.packages = [tuicr];

  # The skill's Rex wrapper reads `rex split --json` with jq (modules/dev-tools.nix).
  home.file.".claude/skills/tuicr".source = skill;
  # Codex and pi read skills here.
  home.file.".agents/skills/tuicr".source = skill;

  xdg.configFile."tuicr/themes/evergarden-winter.toml".source =
    toml.generate "evergarden-winter.toml" evergardenWinter;

  xdg.configFile."tuicr/config.toml".source = toml.generate "tuicr-config.toml" {
    theme = "evergarden-winter";
    # A dark theme on a light terminal background is unreadable; paint its own.
    transparent_background = false;
    # llm-agents moves the version every hour; tuicr's own check only nags.
    no_update_check = true;
    username = config.home.username;
    # The four types tuicr's agent skill tells agents how to act on.
    comment_types = [
      {
        id = "note";
        definition = "a question or remark; answer or acknowledge it";
      }
      {
        id = "suggestion";
        definition = "an improvement to consider; say why if not taken";
      }
      {
        id = "issue";
        definition = "a problem to fix first";
      }
      {
        id = "praise";
        definition = "positive feedback; no action needed";
      }
    ];
  };
}
