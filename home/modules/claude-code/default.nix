{lib, ...}: let
  palettes = {
    evergarden-winter = import ../palettes/evergarden-winter.nix;
    kanso-zen = import ../palettes/kanso-zen.nix;
  };

  # 没列的 token(各种 shimmer 等)落回 base 预设。
  mkTheme = pal: let
    r = pal.roles;
  in {
    inherit (pal) name;
    # base 名里带 dark 时语法高亮是写死的 Monokai,带 ansi 才改用终端 16 色(ghostty 的 kanso)。
    # 代价是 diff 渲染器在 ansi 下把 RGB 底色降成 256 色,所以下面不设 diff 底色,用它原生的样子。
    base = "dark-ansi";
    overrides =
      {
        claude = r.accent;
        claudeShimmer = r.accentShimmer;
        text = r.fg;
        inverseText = r.bg;
        inactive = r.muted;
        subtle = r.faint;
        suggestion = r.blue;
        permission = r.blue;
        remember = r.purple;

        success = r.success;
        error = r.error;
        warning = r.warning;
        warningShimmer = r.warningShimmer;
        merged = r.purple;

        promptBorder = r.border;
        planMode = r.cyan;
        autoAccept = r.purple;
        bashBorder = r.pink;
        ide = r.blue;
        fastMode = r.orange;

        userMessageBackground = r.bgRaised;
        userMessageBackgroundHover = r.bgHover;
        selectionBg = r.bgHover;

        rate_limit_fill = r.accent;
        rate_limit_empty = r.bgHover;
        briefLabelYou = r.blue;
        briefLabelClaude = r.accent;
      }
      // lib.mapAttrs' (n: lib.nameValuePair "${n}_FOR_SUBAGENTS_ONLY") {
        inherit (r) red blue green yellow purple orange pink cyan;
      };
  };
in {
  # Claude Code 在 tmux 里默认降到 256 色,主题里的浅色会被压成灰。这里的 tmux
  # 客户端带 RGB 能力,真彩色能透传;透传不了的终端 tmux 会自己降色。
  home.sessionVariables.CLAUDE_CODE_TMUX_TRUECOLOR = "1";

  # HM 的 programs.claude-code 没有 themes 选项。选用要在 /theme 里点一次:
  # settings.json 不归 nix 管(见 hank/default.nix 里 statusline 那段)。
  home.file = lib.mapAttrs' (slug: pal:
    lib.nameValuePair ".claude/themes/${slug}.json" {
      text = builtins.toJSON (mkTheme pal);
    })
  palettes;
}
