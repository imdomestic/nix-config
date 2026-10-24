{pkgs}: let
  inherit (import ../palettes/kanso-zen.nix) colors;
  rule = scope: settings: {inherit scope settings;};
  colorRule = scope: foreground: rule scope {inherit foreground;};
  # 语法角色对应上游 themes.lua 的 zen.syn,默认饱和度。
  # https://github.com/webhooked/kanso.nvim/blob/1afbbb449aa0254823dbe1932e3cbb51886ff9fe/lua/kanso/themes.lua
  theme = {
    name = "Kanso Zen";
    settings = with colors; [
      {
        settings = {
          foreground = fg;
          background = zenBg0;
          caret = fg;
          selection = zenBg2;
          lineHighlight = zenBg1;
        };
      }
      (rule "comment" {
        foreground = gray4;
        fontStyle = "italic";
      })
      (colorRule "string" green3)
      (colorRule "constant.numeric" pink)
      (colorRule "constant.language, constant.character, entity.name.constant" orange)
      (colorRule "variable.other, variable.language" violet2)
      (colorRule "variable.parameter" gray3)
      (colorRule "entity.name.function, support.function" blue3)
      (colorRule "keyword, storage" violet2)
      (colorRule "keyword.operator, meta.preprocessor, punctuation" gray3)
      (colorRule "entity.name.type, entity.name.class, support.type, support.class" aqua)
      (colorRule "string.regexp" red3)
      (colorRule "constant.character.escape" yellow3)
      (colorRule "entity.name.tag" violet2)
      (colorRule "entity.other.attribute-name" blue3)
      (colorRule "invalid" red)
      (colorRule "markup.inserted" gitGreen)
      (colorRule "markup.deleted" gitRed)
      (colorRule "markup.changed" yellow)
      (rule "markup.heading" {
        foreground = blue3;
        fontStyle = "bold";
      })
      (colorRule "markup.raw" green3)
      (rule "markup.bold" {fontStyle = "bold";})
      (rule "markup.italic" {fontStyle = "italic";})
    ];
  };
  json = pkgs.writeText "kanso-zen-theme.json" (builtins.toJSON theme);
in
  pkgs.runCommand "kanso-zen.tmTheme" {nativeBuildInputs = [pkgs.python3];} ''
    python - ${json} "$out" <<'PY'
    import json, plistlib, sys
    with open(sys.argv[1]) as source, open(sys.argv[2], "wb") as target:
        plistlib.dump(json.load(source), target, sort_keys=False)
    PY
  ''
