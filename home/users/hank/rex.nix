{
  config,
  lib,
  pkgs,
  ...
}: let
  ghostty = config.programs.ghostty;
  last = value: lib.last (lib.toList value);
  fonts = lib.toList ghostty.settings.font-family;
  zenId = "custom-F26A132B-4D31-47EB-87D9-24AED11165C4";
  pearlId = "custom-26E5B310-00BF-40B2-98BC-0268B1FCC6EF";
  themeSource = pkgs.writeText "rex-themes.json" (builtins.toJSON [
    {
      id = zenId;
      name = "Kanso Zen";
      appearance = "dark";
      colors = ghostty.themes.${last ghostty.settings.theme};
    }
    {
      id = pearlId;
      name = "Kanso Pearl";
      appearance = "light";
      # https://github.com/webhooked/kanso.nvim/blob/main/extras/ghostty/kanso-pearl
      colors = {
        background = "#f2f1ef";
        foreground = "#22262D";
        cursor-color = "#22262D";
        selection-background = "#e2e1df";
        selection-foreground = "#22262D";
        palette = [
          "0=#22262D"
          "1=#c84053"
          "2=#6f894e"
          "3=#77713f"
          "4=#4d699b"
          "5=#b35b79"
          "6=#597b75"
          "7=#9F9F99"
          "8=#5C6066"
          "9=#d7474b"
          "10=#6e915f"
          "11=#836f4a"
          "12=#6693bf"
          "13=#624c83"
          "14=#5e857a"
          "15=#f2f1ef"
        ];
      };
    }
  ]);
in {
  # Rex 1408 stores appearance in user defaults, separately from init.lua.
  # Migration coverage and remaining differences: docs/rex.md.
  targets.darwin.defaults."com.superlogical.rex" = {
    "Workspace.darkThemeID" = zenId;
    "Workspace.lightThemeID" = pearlId;
    "Workspace.terminalFontName" = lib.head fonts;
    "Workspace.terminalFontPointSize" = last ghostty.settings.font-size;
    "Workspace.terminalFallbackFontNames" = lib.tail fonts;
    "Workspace.terminalCursorStyle" = last ghostty.settings.cursor-style;
    "Workspace.terminalCursorStyleForced" = false;
    "Workspace.terminalCursorBlinkIntervalMilliseconds" = 0;
    "Workspace.terminalCursorBlinkUsesCustomInterval" = false;
    "Workspace.terminalOptionKeyBehavior" = "actsAsAlt";
    "Workspace.terminalUsesDisplayP3" = false;
  };

  # defaults' native module cannot encode NSData; merge only this JSON-data key.
  home.activation.rexTheme = lib.hm.dag.entryAfter ["setDarwinDefaults"] ''
    run ${lib.getExe pkgs.python3} - ${themeSource} <<'PY'
    import json
    import plistlib
    import subprocess
    import sys
    import tempfile
    import time

    domain = "com.superlogical.rex"
    with open(sys.argv[1]) as source:
        theme_specs = json.load(source)

    def color(hex_value):
        rgb = bytes.fromhex(hex_value.lstrip("#"))
        return dict(zip(("red", "green", "blue"), (v / 255 for v in rgb)),
                    alpha=1, colorSpace="srgb")

    # Match Ghostty's standard xterm colors outside the sixteen theme colors.
    levels = (0, 95, 135, 175, 215, 255)
    extended = {}
    for index in range(16, 256):
        if index < 232:
            n = index - 16
            rgb = (levels[n // 36], levels[n // 6 % 6], levels[n % 6])
        else:
            rgb = (8 + 10 * (index - 232),) * 3
        extended[str(index)] = color(bytes(rgb).hex())

    def palette_for(colors):
        def last(key):
            value = colors[key]
            return value[-1] if isinstance(value, list) else value

        palette = {
            "background": color(last("background")),
            "foreground": color(last("foreground")),
            "cursor": color(last("cursor-color")),
            "cursorText": color(last("background")),
            "selectionBackground": color(last("selection-background")),
            "selectionForeground": color(last("selection-foreground")),
            "ansi": [None] * 16,
            "paletteGenerate": False,
            "paletteHarmonious": False,
            "paletteBase": extended,
            "paletteOverrides": {},
        }
        for entry in colors["palette"]:
            index, hex_value = entry.split("=", 1)
            palette["ansi"][int(index)] = color(hex_value)
        return palette

    result = subprocess.run(["/usr/bin/defaults", "export", domain, "-"],
                            capture_output=True, check=True)
    current = plistlib.loads(result.stdout)
    themes = json.loads(current.get("Workspace.customThemes", b"[]"))
    for spec in theme_specs:
        previous = next((t for t in themes if t["id"] == spec["id"]), {})
        theme = {
            "id": spec["id"],
            "name": spec["name"],
            "appearance": spec["appearance"],
            "source": {"manual": {}},
            "createdAt": previous.get("createdAt", time.time() - 978307200),
            "palette": palette_for(spec["colors"]),
        }
        themes = [t for t in themes if t["id"] != spec["id"]] + [theme]
    data = json.dumps(themes, separators=(",", ":")).encode()
    with tempfile.NamedTemporaryFile(suffix=".plist") as output:
        plistlib.dump({"Workspace.customThemes": data}, output)
        output.flush()
        subprocess.run(["/usr/bin/defaults", "import", domain, output.name],
                       check=True)
    PY
  '';
}
