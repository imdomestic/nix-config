{
  lib,
  buildGoModule,
  stdenv,
}:
buildGoModule {
  pname = "cliproxy-rewind";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  vendorHash = null;
  env.CGO_ENABLED = "1";
  buildPhase = ''
    runHook preBuild
    go build -trimpath -buildmode=c-shared -o rewind${stdenv.hostPlatform.extensions.sharedLibrary} .
    runHook postBuild
  '';
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    go test ./...
    runHook postCheck
  '';
  installPhase = ''
    runHook preInstall
    install -Dm755 rewind${stdenv.hostPlatform.extensions.sharedLibrary} \
      $out/lib/rewind${stdenv.hostPlatform.extensions.sharedLibrary}
    runHook postInstall
  '';
  meta = {
    description = "Rewind Responses provider for the CLIProxyAPI C ABI";
    license = lib.licenses.mit;
    platforms = lib.platforms.unix;
  };
}
