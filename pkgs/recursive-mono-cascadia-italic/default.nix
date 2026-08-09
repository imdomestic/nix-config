{
  lib,
  stdenvNoCC,
  python3,
  nerd-font-patcher,
  nerd-fonts,
  cascadia-code,
}:
# RecMonoSmCasual Nerd Font Mono with Cascadia Code's italics in place of
# Recursive's own -- Recursive's italic is an oblique of the roman, Cascadia's
# is a drawn cursive, which is the whole point of the swap.
#
# This is a drop-in for nerd-fonts.recursive-mono rather than a font of its own:
# it passes the other 46 files through byte-for-byte and only swaps the two
# SmCasual Mono italics. Keeping the family name means nothing downstream has to
# change; making it a replacement rather than an addition means fontconfig never
# sees two different files claiming to be "RecMonoSmCasual Nerd Font Mono
# Italic", which is a coin toss it would resolve on its own.
#
# Only the Mono variant is swapped. RecMonoSmCasual Nerd Font (the default,
# double-width-icon variant) and ...Propo are separate families, so they keep
# Recursive's italic and don't collide with anything here.
let
  inherit (nerd-fonts) recursive-mono;

  python = python3.withPackages (ps: [ps.fonttools ps.brotli]);

  # The styles Cascadia contributes, and the face each comes from. Regular and
  # Bold stay Recursive's.
  #
  # Cascadia's Regular italic renders about 14% more ink than Recursive Mono's
  # roman (measured over an alphanumeric sample at 60px); CascadiaCode-
  # SemiLightItalic comes in about 9% under it. Regular is the closer match to
  # "Cascadia Code italic" as such, so it is the default -- swap the entry below
  # if the italic reads too heavy against the upright text.
  sources = {
    Italic = "CascadiaCode-Italic";
    BoldItalic = "CascadiaCode-BoldItalic";
  };

  recMonoDir = "share/fonts/truetype/NerdFonts/RecMono";
in
  stdenvNoCC.mkDerivation {
    pname = "recursive-mono-cascadia-italic";
    version = "${recursive-mono.version}+cascadia-${cascadia-code.version}";

    dontUnpack = true;

    nativeBuildInputs = [python nerd-font-patcher];

    buildPhase =
      ''
        runHook preBuild

        # fontforge wants somewhere to put its dotfiles.
        export HOME=$NIX_BUILD_TOP
      ''
      + lib.concatStrings (lib.mapAttrsToList (style: source: ''

          python3 ${./prescale.py} \
            ${cascadia-code}/share/fonts/opentype/${source}.otf \
            prescaled-${style}.otf

          # --mono makes every added icon single-width, which is what separates
          # the "Nerd Font Mono" faces from the plain "Nerd Font" ones. The
          # patcher names its output after the font's own name records, so give
          # each run a directory to itself instead of guessing the filename.
          mkdir -p patched-${style}
          nerd-font-patcher --mono --complete --quiet \
            --outputdir patched-${style} prescaled-${style}.otf

          python3 ${./finalize.py} \
            patched-${style}/*.otf \
            RecMonoSmCasualNerdFontMono-${style}.otf \
            ${style}
        '')
        sources)
      + ''

        runHook postBuild
      '';

    installPhase = ''
      runHook preInstall

      mkdir -p $out/share
      cp -r ${recursive-mono}/share/fonts $out/share/fonts
      chmod -R u+w $out/share/fonts

      # The replacements carry CFF outlines rather than glyf, so they leave
      # truetype/ behind. fontconfig and CoreText both go by content, not by
      # directory or extension.
      rm $out/${recMonoDir}/RecMonoSmCasualNerdFontMono-{Italic,BoldItalic}.ttf
      install -Dm444 -t $out/share/fonts/opentype/NerdFonts/RecMono \
        RecMonoSmCasualNerdFontMono-Italic.otf \
        RecMonoSmCasualNerdFontMono-BoldItalic.otf

      runHook postInstall
    '';

    meta = {
      description = "RecMonoSmCasual Nerd Font Mono, with Cascadia Code's italics";
      license = with lib.licenses; [ofl];
      platforms = lib.platforms.all;
    };
  }
