{
  lib,
  buildNpmPackage,
  fetchurl,
  importNpmLock,
  writeText,
}: let
  package = {
    name = "@tintinweb/pi-subagents";
    version = "0.22.1";
    private = true;
    type = "module";
    dependencies = {
      croner = "^10.0.1";
      nanoid = "^5.1.16";
    };
    peerDependencies = {
      "@earendil-works/pi-ai" = "*";
      "@earendil-works/pi-coding-agent" = "*";
      "@earendil-works/pi-tui" = "*";
      typebox = "*";
    };
    pi.extensions = ["./src/index.ts"];
  };
in
  buildNpmPackage {
    pname = "pi-tintin-subagents";
    inherit (package) version;

    src = fetchurl {
      url = "https://registry.npmjs.org/@tintinweb/pi-subagents/-/pi-subagents-${package.version}.tgz";
      hash = "sha512-Z/8o9VtRhkpe0vgeX5I5YVnNWWHg4Obm8SxDiyQQ4ypwoyuMQrA6vn8xcCwZ20y5mYQh4mdjId5Asd/rpJKFUQ==";
    };

    patches = [./compact-fleet.patch];

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
      cp -r src dist docs examples node_modules package.json LICENSE README.md SECURITY.md "$out/"
      runHook postInstall
    '';

    meta = {
      description = "Claude Code style subagents and dynamic workflows for Pi";
      homepage = "https://github.com/tintinweb/pi-subagents";
      license = lib.licenses.mit;
      platforms = lib.platforms.unix;
    };
  }
