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
          hash = lib.fakeHash;
        }}/skills/tuicr $out
        chmod -R u+w $out
        patchShebangs --host $out
      '';

  kansoZen = with (import ./palettes/kanso-zen.nix).colors; {
    panel_bg = zenBg0;
    bg_highlight = zenBg2;
    fg_primary = fg;
    fg_secondary = gray2;
    fg_dim = gray4;

    diff_add = gitGreen;
    diff_add_bg = diffGreen;
    diff_del = gitRed;
    diff_del_bg = diffRed;
    diff_context = fg;
    diff_hunk_header = violet;
    expanded_context_fg = gray4;
    syntax_add_bg = diffGreen;
    syntax_del_bg = diffRed;
    # Codex's Kanso Zen syntax theme; tuicr reads .tmTheme files too.
    syntax_theme = "${import ./codex/kanso-zen.nix {inherit pkgs;}}";

    file_added = gitGreen;
    file_modified = yellow;
    file_deleted = gitRed;
    file_renamed = violet;
    reviewed = green;
    pending = yellow;

    comment_note = blue;
    comment_suggestion = aqua;
    comment_issue = red;
    comment_praise = green;

    border_focused = blue3;
    border_unfocused = zenBg3;
    status_bar_bg = zenBg1;
    cursor_color = yellow2;
    cursor_line_bg = zenBg1;
    branch_name = violet;
    help_indicator = gray4;

    message_info_fg = zenBg0;
    message_info_bg = blue3;
    message_warning_fg = zenBg0;
    message_warning_bg = yellow;
    message_error_fg = zenBg0;
    message_error_bg = red;
    update_badge_fg = zenBg0;
    update_badge_bg = yellow;
    mode_fg = zenBg0;
    mode_bg = blue3;
  };
in {
  home.packages = [tuicr];

  # The skill's Rex wrapper reads `rex split --json` with jq (modules/dev-tools.nix).
  home.file.".claude/skills/tuicr".source = skill;
  # Codex and pi read skills here.
  home.file.".agents/skills/tuicr".source = skill;

  xdg.configFile."tuicr/themes/kanso-zen.toml".source = toml.generate "kanso-zen.toml" kansoZen;

  xdg.configFile."tuicr/config.toml".source = toml.generate "tuicr-config.toml" {
    theme = "kanso-zen";
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
