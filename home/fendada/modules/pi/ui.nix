{
  lib,
  stdenv,
  autoPatchelfHook,
  buildNpmPackage,
  importNpmLock,
}:
buildNpmPackage {
  pname = "fendada-pi-ui";
  version = "1.0.0";
  src = ./ui;
  npmDeps = importNpmLock {npmRoot = ./ui;};
  npmConfigHook = importNpmLock.npmConfigHook;
  npmFlags = ["--legacy-peer-deps" "--ignore-scripts"];
  dontNpmBuild = true;
  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [autoPatchelfHook];
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [stdenv.cc.cc.lib];

  # Keep the Windows-local code frames without vendoring upstream or Windows binaries.
  installPhase = ''
    runHook preInstall
    chmod -R u+w node_modules/pi-better-render
    patch -d node_modules/pi-better-render -p1 < ${./framed-code.patch}
    mkdir -p "$out"
    cp -r node_modules "$out/"
    runHook postInstall
  '';
  postInstall = lib.optionalString stdenv.hostPlatform.isLinux ''
    find "$out/node_modules/@resvg" -maxdepth 1 -type d -name '*-musl' -exec rm -rf {} +
  '';
  meta.platforms = lib.platforms.unix;
}
