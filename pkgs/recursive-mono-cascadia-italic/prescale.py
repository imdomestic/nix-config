"""Put Cascadia Code on Recursive Mono's grid, before the Nerd Font patcher runs.

Cascadia is 2048 upem with a 1200-unit advance (0.586 em); Recursive Mono is
1000 upem with a 600-unit advance (0.6 em). Halving every coordinate (2048 ->
1024 is exact) lands the advance on 600. The em stays at 1024 here rather than
going straight to 1000, because fontforge reads the em out of the CFF
FontMatrix and would overwrite a head.unitsPerEm that disagrees with it;
finalize.py relabels the em as 1000 once the patcher is done, and that relabel
is what turns the 600-unit advance into 0.6 em.

Net effect on the glyphs: 2.4% larger relative to the em, which lands Cascadia's
cap height at 0.71 em against Recursive's 0.70 and its x-height at 0.53 against
0.54 -- close enough that the two styles read as one size.

The vertical metrics are put on Recursive's proportions here rather than in
finalize.py so that the patcher scales the icons into the cell Recursive's own
icons live in.
"""

import sys

from fontTools.ttLib import TTFont
from fontTools.ttLib.scaleUpem import scale_upem

src, dst = sys.argv[1], sys.argv[2]

INTERMEDIATE_UPEM = 1024
ASCENDER = round(0.95 * INTERMEDIATE_UPEM)  # Recursive Mono: 950 at 1000 upem
DESCENDER = round(0.25 * INTERMEDIATE_UPEM)  # Recursive Mono: 250 at 1000 upem

font = TTFont(src)
scale_upem(font, INTERMEDIATE_UPEM)

hhea = font["hhea"]
hhea.ascender, hhea.descender, hhea.lineGap = ASCENDER, -DESCENDER, 0

os2 = font["OS/2"]
os2.sTypoAscender, os2.sTypoDescender, os2.sTypoLineGap = ASCENDER, -DESCENDER, 0
os2.usWinAscent, os2.usWinDescent = ASCENDER, DESCENDER

font.save(dst)
