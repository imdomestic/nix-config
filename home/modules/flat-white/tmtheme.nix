{pkgs}: let
  c = (import ../palettes/flat-white.nix).colors;
  rule = scope: foreground: {
    inherit scope;
    settings = {inherit foreground;};
  };
  theme = {
    name = "Flat White";
    settings = [
      {
        settings = {
          inherit (c) background foreground;
          caret = c.cursor;
          selection = c.selection_bg;
          lineHighlight = c.color0;
        };
      }
      {
        scope = "comment";
        settings = {
          foreground = c.color8;
          fontStyle = "italic";
        };
      }
      (rule "string, markup.raw" c.color2)
      (rule "constant.numeric, constant.language, constant.character" c.color5)
      (rule "keyword, storage" c.color3)
      (rule "entity.name.function, support.function" c.color4)
      (rule "entity.name.type, entity.name.class, support.type, support.class" c.color6)
      (rule "variable, punctuation" c.foreground)
      (rule "keyword.operator, entity.other.attribute-name" c.color6)
      (rule "entity.name.tag" c.color3)
      (rule "string.regexp, constant.character.escape" c.color11)
      (rule "invalid, markup.deleted" c.color1)
      (rule "markup.inserted" c.color2)
      (rule "markup.changed" c.color3)
      {
        scope = "markup.heading";
        settings = {
          foreground = c.color4;
          fontStyle = "bold";
        };
      }
      {
        scope = "markup.bold";
        settings.fontStyle = "bold";
      }
      {
        scope = "markup.italic";
        settings.fontStyle = "italic";
      }
    ];
  };
  json = pkgs.writeText "flat-white-theme.json" (builtins.toJSON theme);
in
  pkgs.runCommand "flat-white.tmTheme" {nativeBuildInputs = [pkgs.python3];} ''
    python - ${json} "$out" <<'PY'
    import json, plistlib, sys
    with open(sys.argv[1]) as source, open(sys.argv[2], "wb") as target:
        plistlib.dump(json.load(source), target, sort_keys=False)
    PY
  ''
