{
  lib,
  stdenv,
  autoPatchelfHook,
  buildNpmPackage,
  fetchurl,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "pi-better-render";
    version = "0.4.0";
    private = true;
    type = "module";
    dependencies = {
      "@resvg/resvg-js" = "^2.6.2";
      # Bundle the upstream lazy dependency so diagrams never run npm at runtime.
      beautiful-mermaid = "1.1.3";
    };
    peerDependencies = {
      "@earendil-works/pi-coding-agent" = "*";
      "@earendil-works/pi-tui" = "*";
    };
    pi.extensions = ["./src/index.ts"];
  };
in
  buildNpmPackage ({
      pname = package.name;
      inherit (package) version;

      src = fetchurl {
        url = "https://registry.npmjs.org/pi-better-render/-/pi-better-render-${package.version}.tgz";
        hash = "sha256-LB9K/naejepIIydXmPD/jtb2yYBs1iU7s3DXa6AZOCo=";
      };

      # Rex supports text-anchored Kitty images; direct placements leave ghosts.
      patches = [./rex-placeholders.patch];

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
        cp -r src vendor node_modules package.json LICENSE README.md "$out/"
        runHook postInstall
      '';

      meta = {
        description = "Streaming Markdown and inline LaTeX rendering for the Pi terminal UI";
        homepage = "https://github.com/JeffeyChou/pi-better-render";
        license = lib.licenses.mit;
        platforms = ["aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux"];
      };
    }
    // lib.optionalAttrs stdenv.hostPlatform.isLinux {
      # The optional musl binaries cannot run or be patched on glibc hosts.
      postInstall = ''
        find "$out/node_modules" -maxdepth 2 -type d -name '*-musl' -prune -exec rm -rf {} +
      '';
    })
