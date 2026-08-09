"""Relabel the patched Cascadia italic as a RecMonoSmCasual Nerd Font Mono face.

Two jobs. First, finish the rescale prescale.py set up: fontforge writes the em
back out as 1024, which would leave the advance at 0.586 em again. Relabelling
the em as 1000 -- without touching a single coordinate -- makes the 600-unit
advance exactly 0.6 em, so the italic sits on the same cell as the Regular and
Bold faces it ships alongside.

Second, rename the font into the family the rest of the RecMono files form.
Copyright, licence, designer and vendor records are left alone: the outlines in
this file are Cascadia's, so they stay credited to Microsoft and Saja Typeworks.
"""

import sys

from fontTools.ttLib import TTFont

src, dst, style = sys.argv[1], sys.argv[2], sys.argv[3]

FAMILY = "RecMonoSmCasual Nerd Font Mono"
SUBFAMILY = {"Italic": "Italic", "BoldItalic": "Bold Italic"}[style]

UPEM = 1000
ASCENDER, DESCENDER = 950, 250  # Recursive Mono's own vertical metrics
ADVANCE = 600

font = TTFont(src)

font["head"].unitsPerEm = UPEM
top = font["CFF "].cff.topDictIndex[0]
assert not hasattr(top, "FDArray"), "CID-keyed CFF needs per-FD FontMatrix handling"
top.FontMatrix = [1.0 / UPEM, 0, 0, 1.0 / UPEM, 0, 0]

hhea = font["hhea"]
hhea.ascender, hhea.descender, hhea.lineGap = ASCENDER, -DESCENDER, 0

os2 = font["OS/2"]
os2.sTypoAscender, os2.sTypoDescender, os2.sTypoLineGap = ASCENDER, -DESCENDER, 0
os2.usWinAscent, os2.usWinDescent = ASCENDER, DESCENDER
os2.xAvgCharWidth = ADVANCE
os2.fsSelection |= 0x180  # USE_TYPO_METRICS + WWS, matching the RecMono faces

name = font["name"]
version = name.getDebugName(5)
records = {
    1: FAMILY,
    2: SUBFAMILY,
    3: f"{FAMILY} {SUBFAMILY}; {version}",  # unique ID, must not collide
    4: f"{FAMILY} {SUBFAMILY}",
    6: f"RecMonoSmCasualNFM-{style}",
}
for name_id, value in records.items():
    name.setName(value, name_id, 1, 0, 0)  # Macintosh
    name.setName(value, name_id, 3, 1, 0x409)  # Windows, en-US

advance = font["hmtx"]["a"][0]
assert advance == ADVANCE, f"advance is {advance}, expected {ADVANCE}"

font.save(dst)
