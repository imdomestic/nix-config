{
  lib,
  stdenvNoCC,
  fetchFromGitHub,
  glib,
  python3,
}: let
  extensionUuid = "appmenu@ChathurangaBW.github.io";
in
  stdenvNoCC.mkDerivation {
    pname = "gnome-shell-extension-appmenu";
    version = "5.6.2";

    src = fetchFromGitHub {
      owner = "ChathurangaBW";
      repo = "AppMenu";
      rev = "0e2cbb366875133f8eb0ce3fff248a4894df0723";
      hash = "sha256-b0eU2IVyaipJD8M9hnP+wEmuFSaYSr8sjjwJR/3XfUE=";
    };

    nativeBuildInputs = [glib python3];
    dontConfigure = true;
    # Scope the distro-icon rule so it cannot resize GNOME's status icons.
    postPatch = ''
      substituteInPlace stylesheet.css \
        --replace-fail '.system-status-icon {' '.appmenu-panel-button .system-status-icon {'
    '';
    buildPhase = ''
      runHook preBuild
      glib-compile-schemas --strict schemas
      python3 build-locale.py compile
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      extensionDir="$out/share/gnome-shell/extensions/${extensionUuid}"
      mkdir -p "$extensionDir"
      cp -r *.js *.css metadata.json icons.json actions menus icons locale schemas "$extensionDir/"
      runHook postInstall
    '';

    passthru = {inherit extensionUuid;};
    meta = {
      description = "Application menus in the GNOME top panel, with shortcut fallbacks";
      homepage = "https://github.com/ChathurangaBW/AppMenu";
      license = lib.licenses.gpl3Plus;
      platforms = lib.platforms.linux;
    };
  }
