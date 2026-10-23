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
    name = "opencode-latex";
    version = "0.2.0";
    private = true;
    type = "module";
    # Match OpenCode 2.1.x's native runtime; see docs/incidents.md#opencode-latex-opentui-06.
    dependencies = {
      "@opentui/core" = "0.6.6";
      "opentui-math" = "0.1.0";
    };
  };
in
  buildNpmPackage {
    pname = package.name;
    inherit (package) version;

    src = fetchurl {
      url = "https://registry.npmjs.org/opencode-latex/-/opencode-latex-${package.version}.tgz";
      hash = "sha512-OVKCZWv4HCG8wyDgUn2gzJXDwEsIpahAvsAiH2ngLgCoCbgquBYznbmsPbS2k8Kp++0W4DJ7uuTiAAyWk3Pa2Q==";
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
    # Patch the installed math dependency as well as the plugin's transport.
    preInstall = ''
      patch --batch -p1 < ${./opentui-0.6.patch}
    '';
    dontNpmBuild = true;
    nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [autoPatchelfHook];
    buildInputs = lib.optionals stdenv.hostPlatform.isLinux [stdenv.cc.cc.lib];

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -r src node_modules package.json LICENSE "$out/"
      echo 'export { default } from "./src/index.ts"' > "$out/index.ts"
      echo 'export { default } from "./src/tui.ts"' > "$out/tui.ts"
      runHook postInstall
    '';

    meta = {
      description = "OpenCode 2 LaTeX renderer with compatible OpenTUI dependencies";
      homepage = "https://github.com/kriss-spy/opencode-latex";
      license = lib.licenses.mit;
      platforms = ["aarch64-darwin" "x86_64-linux" "aarch64-linux"];
    };
  }
