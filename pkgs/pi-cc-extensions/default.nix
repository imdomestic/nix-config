{
  lib,
  buildNpmPackage,
  fetchurl,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "pi-cc-extensions";
    version = "1.0.8";
    private = true;
    type = "module";
    dependencies = {
      "@shikijs/cli" = "^4.0.2";
      "grok-mermaid" = "^0.2.2";
      jiti = "^2.7.0";
    };
    peerDependencies = {
      "@earendil-works/pi-ai" = "*";
      "@earendil-works/pi-coding-agent" = "*";
      "@earendil-works/pi-tui" = "*";
    };
    pi = {
      extensions = ["./extensions/index.ts"];
      themes = ["./themes/cc-dark.json" "./themes/cc-light.json"];
    };
  };
in
  buildNpmPackage {
    pname = package.name;
    inherit (package) version;

    src = fetchurl {
      url = "https://registry.npmjs.org/pi-cc-extensions/-/pi-cc-extensions-${package.version}.tgz";
      hash = "sha512-f25RCxUyWCxYfJI4rlErVQpnW4H5iEnrbAtRBpTcAI2iOFZt4lwDWFgQjGAy6VbIJP36RpNyXHSuPpguQkelZg==";
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

    installPhase = ''
      runHook preInstall
      mkdir -p "$out"
      cp -r extensions themes node_modules package.json LICENSE README.md "$out/"
      runHook postInstall
    '';

    meta = {
      description = "Claude Code style rendering and themes for Pi";
      homepage = "https://github.com/minuque/pi-cc-extensions";
      license = lib.licenses.mit;
      platforms = lib.platforms.unix;
    };
  }
