{
  lib,
  stdenv,
}: let
  info = builtins.toFile "safari-mru-Info.plist" (lib.generators.toPlist {escape = true;} {
    CFBundleIdentifier = "com.imdomestic.safari-mru";
    CFBundleName = "Safari MRU";
    CFBundleExecutable = "safari-mru";
    CFBundlePackageType = "APPL";
    CFBundleVersion = "2";
    LSUIElement = true;
    NSAccessibilityUsageDescription = "Switch Safari tabs in most recently used order with Control-Tab.";
  });
in
  stdenv.mkDerivation {
    pname = "safari-mru";
    version = "2";
    src = ./.;
    dontConfigure = true;

    buildPhase = ''
      runHook preBuild
      $CC -fobjc-arc -O2 -Wall -Wextra -Werror main.m history.m -o safari-mru \
        -framework Cocoa -framework ApplicationServices -framework Carbon
      runHook postBuild
    '';

    doCheck = true;
    checkPhase = ''
      runHook preCheck
      $CC -fobjc-arc -O2 -Wall -Wextra -Werror test.m history.m -o test-history -framework Foundation
      ./test-history
      runHook postCheck
    '';

    installPhase = ''
      runHook preInstall
      app="$out/Applications/Safari MRU.app"
      mkdir -p "$app/Contents/MacOS" "$out/bin"
      cp safari-mru "$app/Contents/MacOS/"
      cp ${info} "$app/Contents/Info.plist"
      ln -s "$app/Contents/MacOS/safari-mru" "$out/bin/safari-mru"
      runHook postInstall
    '';

    meta = {
      description = "Invisible Safari Control-Tab MRU switcher using Accessibility";
      platforms = lib.platforms.darwin;
      mainProgram = "safari-mru";
    };
  }
