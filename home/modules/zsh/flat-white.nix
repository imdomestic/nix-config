{
  config,
  lib,
  ...
}: let
  palette = import ../palettes/flat-white.nix;
  c = palette.colors;
  fzfColors = lib.concatStringsSep "," (lib.mapAttrsToList (name: color: "${name}:${color}") config.programs.fzf.colors);
  styles = {
    default = "none";
    unknown-token = "fg=${c.color1},bold";
    reserved-word = "fg=${c.color3}";
    subcommand = "fg=${c.color4}";
    alias = "fg=${c.color4}";
    suffix-alias = "fg=${c.color4}";
    global-alias = "fg=${c.color5}";
    builtin = "fg=${c.color4}";
    function = "fg=${c.color4}";
    command = "fg=${c.color4}";
    precommand = "fg=${c.color3}";
    hashed-command = "fg=${c.color4}";
    commandseparator = "fg=${c.color8}";
    redirection = "fg=${c.color6}";
    comment = "fg=${c.color8},italic";
    path = "fg=${c.foreground},underline";
    path-to-dir = "fg=${c.color4},underline";
    pathseparator = "fg=${c.color8}";
    globbing = "fg=${c.color5}";
    globbing-ext = "fg=${c.color13}";
    single-hyphen-option = "fg=${c.color6}";
    double-hyphen-option = "fg=${c.color6}";
    single-quoted-argument = "fg=${c.color2}";
    double-quoted-argument = "fg=${c.color2}";
    dollar-quoted-argument = "fg=${c.color2}";
    back-quoted-argument = "fg=${c.color6}";
    back-dollar-quoted-argument = "fg=${c.color6}";
    back-or-dollar-double-quoted-argument = "fg=${c.color6}";
    variable = "fg=${c.foreground}";
    assign = "fg=${c.foreground}";
    assign-array-bracket = "fg=${c.color6}";
    history-expansion = "fg=${c.color5}";
    mathvar = "fg=${c.color4}";
    mathnum = "fg=${c.color5}";
    matherr = "fg=${c.color1}";
    paired-bracket = "fg=${c.foreground},bg=${c.selection_bg}";
    bracket-level-1 = "fg=${c.color2}";
    bracket-level-2 = "fg=${c.color3}";
    bracket-level-3 = "fg=${c.color6}";
    here-string-tri = "fg=${c.color3}";
    here-string-text = "fg=${c.color2}";
    here-string-var = "fg=${c.color6}";
    exec-descriptor = "fg=${c.color3}";
    correct-subtle = "fg=${c.color4}";
    incorrect-subtle = "fg=${c.color1}";
    subtle-separator = "fg=${c.color2}";
    subtle-bg = "bg=${c.color0}";
    forvar = "fg=${c.foreground}";
    fornum = "fg=${c.color5}";
    foroper = "fg=${c.color3}";
    forsep = "fg=${c.color3}";
    case-input = "fg=${c.color2}";
    case-parentheses = "fg=${c.color3}";
    case-condition = "fg=${c.color4}";
    single-sq-bracket = "fg=${c.color6}";
    double-sq-bracket = "fg=${c.color6}";
    double-paren = "fg=${c.color3}";
  };
in {
  programs.zsh.initContent = lib.mkMerge [
    (lib.mkOrder 450 (lib.concatStringsSep "\n" (lib.imap0 (i: color: "color${toString i}=${lib.escapeShellArg color}") palette.ansi)))
    (lib.mkAfter ''
      # 外部 env.zsh 的色值必须在其加载后覆盖，prompt 继续使用 HM 生成的配置。
      export STARSHIP_CONFIG=${lib.escapeShellArg config.programs.starship.configPath}
      export starship_config="$STARSHIP_CONFIG"
      ${lib.optionalString config.programs.fzf.enable ''
        export FZF_DEFAULT_OPTS=${lib.escapeShellArg (lib.concatStringsSep " " config.programs.fzf.defaultOptions + " --color=" + fzfColors)}
        zstyle ':fzf-tab:*' fzf-flags ${lib.escapeShellArg ("--color=" + fzfColors)}
      ''}
      ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=${c.color8}'
      zle_highlight=("region:fg=${c.selection_fg},bg=${c.selection_bg}" "paste:fg=${c.selection_fg},bg=${c.selection_bg}")
      if (( ''${+FAST_HIGHLIGHT_STYLES} )); then
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: style: ''        FAST_HIGHLIGHT_STYLES[default${name}]=${lib.escapeShellArg style}
                FAST_HIGHLIGHT_STYLES[free${name}]=${lib.escapeShellArg style}'')
      styles)}
      fi
      export LS_COLORS='di=1;34:ln=36:or=31:mi=31:so=35:pi=33:ex=32:bd=33:cd=33:su=1;31:sg=1;33:tw=1;32:ow=34:st=34:*.zip=35:*.tar=35:*.gz=35:*.7z=35:*.jpg=33:*.png=33:*.mp4=35:*.pdf=36'
      zstyle ':completion:*' list-colors ''${(s.:.)LS_COLORS}
      alias sr='source "$ZDOTDIR/.zshrc"'
    '')
  ];
}
