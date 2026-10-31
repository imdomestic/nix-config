{
  lib,
  stdenv,
  autoPatchelfHook,
  patchelfUnstable,
  buildNpmPackage,
  fetchurl,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "@cortexkit/pi-magic-context";
    version = "0.49.33";
    private = true;
    type = "module";
    dependencies = {
      zod = "^4.6.6";
      ai-tokenizer = "^1.0.6";
      comment-json = "^5.0.0";
      onnxruntime-web = "1.26.0-dev.20260416-b7804b056c";
      quickjs-emscripten = "^0.32.0";
      "@cortexkit/subc-client" = "0.11.1";
      "@jitl/quickjs-singlefile-cjs-release-asyncify" = "0.32.0";
    };
    optionalDependencies = {
      sharp = "^0.35.0";
      onnxruntime-node = "1.30.0";
    };
    peerDependencies = {
      "@earendil-works/pi-coding-agent" = "*";
      "@earendil-works/pi-tui" = "*";
      typebox = "*";
    };
    pi.extensions = ["./dist/index.js"];
  };
in
  buildNpmPackage ({
      pname = "pi-magic-context";
      inherit (package) version;

      src = fetchurl {
        url = "https://registry.npmjs.org/@cortexkit/pi-magic-context/-/pi-magic-context-${package.version}.tgz";
        hash = "sha512-H52qdV5QbDKELLoc54QJYCVdYYli1iX7Ib8jLpLfgHa2yzne7MyT4nEZ1ccmecn0b6OwJEkEZTaZKsIzVz2gNw==";
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
        cp -r dist node_modules package.json README.md "$out/"
        runHook postInstall
      '';

      meta = {
        description = "Cross-session memory and context management for Pi";
        homepage = "https://github.com/cortexkit/magic-context";
        license = lib.licenses.mit;
        platforms = ["aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux"];
      };
    }
    // lib.optionalAttrs stdenv.hostPlatform.isLinux {
      # Only the host's glibc native libraries can be patched on Linux.
      # 0.15.2 corrupts libvips' low-address .init; docs/incidents.md#pi-magic-context-patchelf.
      preFixup = ''
        export PATH=${patchelfUnstable}/bin:$PATH
      '';
      postInstall = ''
        find "$out/node_modules" -maxdepth 2 -type d -name '*linuxmusl*' -prune -exec rm -rf {} +
        native="$out/node_modules/onnxruntime-node/bin/napi-v6"
        find "$native" -mindepth 1 -maxdepth 1 ! -name linux -exec rm -rf {} +
        find "$native/linux" -mindepth 1 -maxdepth 1 ! -name ${
          if stdenv.hostPlatform.isAarch64
          then "arm64"
          else "x64"
        } -exec rm -rf {} +
      '';
    })
