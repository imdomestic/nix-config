{
  lib,
  stdenv,
  darwin,
  fetchFromGitHub,
  libplist,
  makeBinaryWrapper,
}: let
  # nixpkgs' 0.1.3 signs standalone Mach-O files, not complete app bundles.
  bundleSigtool = darwin.sigtool.overrideAttrs (old: {
    version = "0.1.3-unstable-2026-11-06";
    src = fetchFromGitHub {
      owner = "nix-community";
      repo = "sigtool";
      rev = "de5de43c5f8bd97bce4de4a8cfc1b3708074a2b2";
      hash = "sha256-VWe+SPQqDPtrAIZf1k6w5Eg4+ofAxlhr/qYCDxvpfOA=";
    };
    patches = [];
    buildInputs = old.buildInputs ++ [libplist];
  });
  info = builtins.toFile "safari-mru-Info.plist" (lib.generators.toPlist {escape = true;} {
    CFBundleIdentifier = "com.imdomestic.safari-mru";
    CFBundleName = "Safari MRU";
    CFBundleExecutable = "safari-mru";
    CFBundlePackageType = "APPL";
    CFBundleVersion = "4";
    LSUIElement = true;
    NSAccessibilityUsageDescription = "Switch Safari tabs in most recently used order with Control-Tab.";
  });
in
  stdenv.mkDerivation {
    pname = "safari-mru";
    version = "4";
    src = ./.;
    dontConfigure = true;
    nativeBuildInputs = [bundleSigtool makeBinaryWrapper];

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
      $CC -fobjc-arc -O2 -Wall -Wextra -Werror verify-bundle.m -o verify-bundle \
        -framework Foundation -framework Security
      runHook postCheck
    '';

    # Signing after strip/fixup seals the final executable, Info.plist and resources.
    postFixup = ''
      codesign -f -s - "$out/Applications/Safari MRU.app"
    '';

    doInstallCheck = true;
    installCheckPhase = ''
      runHook preInstallCheck
      ./verify-bundle "$out/Applications/Safari MRU.app"
      cp -R "$out/Applications/Safari MRU.app" tampered.app
      chmod -R u+w tampered.app
      printf '\n' >> tampered.app/Contents/Info.plist
      if ./verify-bundle tampered.app; then
        echo "Signature verification incorrectly accepted a modified Info.plist" >&2
        exit 1
      fi
      runHook postInstallCheck
    '';

    installPhase = ''
      runHook preInstall
      app="$out/Applications/Safari MRU.app"
      mkdir -p "$app/Contents/MacOS" "$out/bin"
      cp safari-mru "$app/Contents/MacOS/"
      cp ${info} "$app/Contents/Info.plist"
      makeWrapper "$app/Contents/MacOS/safari-mru" "$out/bin/safari-mru"
      runHook postInstall
    '';

    meta = {
      description = "Invisible Safari Control-Tab MRU switcher using Accessibility";
      platforms = lib.platforms.darwin;
      mainProgram = "safari-mru";
    };
  }
