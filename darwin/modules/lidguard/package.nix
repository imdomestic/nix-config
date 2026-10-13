{
  lib,
  swift,
  swiftPackages,
}:
swiftPackages.stdenv.mkDerivation {
  pname = "lidguard";
  version = "1.0.0";

  src = ./lidguard.swift;
  dontUnpack = true;
  nativeBuildInputs = [swift];

  buildPhase = ''
    runHook preBuild
    swiftc -O -framework IOKit -framework Foundation "$src" -o lidguard
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 lidguard "$out/bin/lidguard"
    runHook postInstall
  '';

  meta = {
    description = "Event-driven macOS lid and power-source sleep management";
    platforms = lib.platforms.darwin;
    mainProgram = "lidguard";
  };
}
