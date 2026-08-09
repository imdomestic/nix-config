"""Make Cascadia's cursive italic the default letterforms.

Cascadia's italic ships two designs. The default is a slanted roman; the
cursive one -- the looped descending f, the curled l, the handwritten r and s --
sits behind the ss01 stylistic set. The cursive is the one worth swapping
Recursive's oblique for, so this makes it the default.

The swap is done on the outlines, not the cmap: exchanging what the glyph names
`f` and `f.salt` point at leaves every GSUB rule that mentions `f` -- ligatures,
calt, the lot -- matching the same glyph name it always did. Remapping the cmap
instead would hand those rules a glyph they have never heard of and silently
kill the ligatures.

A side effect worth knowing: ss01 still substitutes `f` -> `f.salt`, so in the
finished font that feature now toggles *back* to the non-cursive design.
"""

import sys

from fontTools.ttLib import TTFont

src, dst = sys.argv[1], sys.argv[2]

font = TTFont(src)

gsub = font["GSUB"].table
lookups = gsub.LookupList.Lookup
mapping = {}
for record in gsub.FeatureList.FeatureRecord:
    if record.FeatureTag != "ss01":
        continue
    for index in record.Feature.LookupListIndex:
        lookup = lookups[index]
        for subtable in lookup.SubTable:
            # Anything other than a plain one-for-one substitution would need
            # more than an outline swap, so refuse rather than half-apply it.
            assert subtable.LookupType == 1, f"ss01 lookup type {subtable.LookupType}"
            mapping.update(subtable.mapping)

assert mapping, "no ss01 substitutions found -- has Cascadia changed?"

charstrings = font["CFF "].cff[font["CFF "].cff.fontNames[0]].CharStrings.charStrings
metrics = font["hmtx"].metrics
for base, alt in mapping.items():
    charstrings[base], charstrings[alt] = charstrings[alt], charstrings[base]
    metrics[base], metrics[alt] = metrics[alt], metrics[base]

print(f"cursive: swapped {len(mapping)} glyphs, e.g. {sorted(mapping)[:6]}")
font.save(dst)
