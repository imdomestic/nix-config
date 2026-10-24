import json
import plistlib
import subprocess
import sys
import time


def color(value):
    red, green, blue = bytes.fromhex(value.removeprefix("#"))
    return {
        "red": red / 255,
        "green": green / 255,
        "blue": blue / 255,
        "alpha": 1,
        "colorSpace": "srgb",
    }


with open(sys.argv[1]) as source:
    spec = json.load(source)

colors = spec["colors"]
levels = (0, 95, 135, 175, 215, 255)
extended = {}
for index in range(16, 256):
    if index < 232:
        offset = index - 16
        rgb = (levels[offset // 36], levels[offset // 6 % 6], levels[offset % 6])
    else:
        rgb = (8 + 10 * (index - 232),) * 3
    extended[str(index)] = color(bytes(rgb).hex())

domain = "com.superlogical.rex"
result = subprocess.run(
    ["/usr/bin/defaults", "export", domain, "-"], capture_output=True, check=True
)
current = plistlib.loads(result.stdout)
themes = json.loads(current.get("Workspace.customThemes", b"[]"))
previous = next((theme for theme in themes if theme["id"] == spec["id"]), {})
theme = {
    "id": spec["id"],
    "name": spec["name"],
    "appearance": "dark",
    "createdAt": previous.get("createdAt", time.time() - 978307200),
    "source": {"manual": {}},
    "palette": {
        "background": color(colors["background"]),
        "foreground": color(colors["foreground"]),
        "cursor": color(colors["cursor"]),
        "cursorText": color(colors["cursor_text"]),
        "selectionBackground": color(colors["selection_bg"]),
        "selectionForeground": color(colors["selection_fg"]),
        "ansi": [color(value) for value in spec["ansi"]],
        "paletteGenerate": False,
        "paletteHarmonious": False,
        "paletteBase": extended,
        "paletteOverrides": {},
    },
}
themes = [entry for entry in themes if entry["id"] != spec["id"]] + [theme]
payload = plistlib.dumps({"Workspace.customThemes": json.dumps(themes).encode()})
subprocess.run(["/usr/bin/defaults", "import", domain, "-"], input=payload, check=True)
