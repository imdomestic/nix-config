{
  lib,
  stdenv,
  autoPatchelfHook,
  buildNpmPackage,
  fetchFromGitHub,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "@fadouse/pi-math";
    version = "0.2.0";
    private = true;
    type = "module";
    dependencies = {
      "@resvg/resvg-js" = "^2.6.2";
      "mathjax-full" = "^3.2.2";
    };
    peerDependencies = {
      "@earendil-works/pi-coding-agent" = "*";
      "@earendil-works/pi-tui" = "*";
    };
    pi.extensions = ["./src/index.ts"];
  };
in
  buildNpmPackage ({
      pname = "pi-math";
      inherit (package) version;

      src = fetchFromGitHub {
        owner = "Fadouse";
        repo = "pi-math";
        rev = "7e6aa628e52998265a7acaba84ff571dbfa557dd";
        hash = "sha256-+6UAladCOqkJbouBbUjSaKvWa02BWP6Uqj32NMX3pDo=";
      };

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
      nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [autoPatchelfHook];
      buildInputs = lib.optionals stdenv.hostPlatform.isLinux [stdenv.cc.cc.lib];

      installPhase = ''
        runHook preInstall
        mkdir -p "$out"
        cp -r src node_modules package.json LICENSE README.md "$out/"
        runHook postInstall
      '';

      meta = {
        description = "Inline LaTeX images for the Pi terminal UI";
        homepage = "https://github.com/Fadouse/pi-math";
        license = lib.licenses.mit;
        platforms = ["aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux"];
      };
    }
    # The lock also carries the musl builds of the native modules; on glibc they
    # can neither run nor be patched, and autoPatchelf fails on them.
    // lib.optionalAttrs stdenv.hostPlatform.isLinux {
      postInstall = ''
        find "$out/node_modules" -maxdepth 2 -type d -name '*-musl' -prune -exec rm -rf {} +
      '';
    })
