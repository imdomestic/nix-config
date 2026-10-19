{
  lib,
  buildNpmPackage,
  fetchurl,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "@zigai/pi-response-renderer";
    version = "0.2.0";
    private = true;
    type = "module";
    dependencies."@zigai/pi-extension-internals" = "0.2.0";
    peerDependencies = {
      "@earendil-works/pi-coding-agent" = "^1.0.0";
      "@earendil-works/pi-tui" = "^1.0.0";
    };
    pi.extensions = ["./src/index.ts"];
  };
in
  buildNpmPackage {
    pname = "pi-response-renderer";
    inherit (package) version;

    src = fetchurl {
      url = "https://registry.npmjs.org/@zigai/pi-response-renderer/-/pi-response-renderer-${package.version}.tgz";
      hash = "sha512-2wUyK3z40G0n3JwKhJZuETTpr+AjDPthCZxXm6REWztlgepGjgHbrwya586FOHPn/Y0ee5B2b4Ck6A8DnCNAsQ==";
    };

    # Keep image placement colors intact; see docs/incidents.md#pi-inline-color-parameters.
    patches = [./preserve-ansi-colors.patch];

    postPatch = ''
      cp ${writeText "package.json" (builtins.toJSON package)} package.json
      cp ${./package-lock.json} package-lock.json
    '';

    npmDeps = importNpmLock {
      inherit package;
      packageLock = lib.importJSON ./package-lock.json;
    };
    npmConfigHook = importNpmLock.npmConfigHook;
    npmFlags = ["--legacy-peer-deps" "--ignore-scripts"];
    dontNpmBuild = true;

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -r src node_modules package.json README.md "$out/"
      runHook postInstall
    '';

    meta = {
      description = "Compact Markdown responses in the Pi terminal UI";
      homepage = "https://github.com/zigai/pi-tweaks";
      license = lib.licenses.mit;
      platforms = lib.platforms.unix;
    };
  }
