{
  lib,
  buildGoModule,
}:
buildGoModule {
  pname = "agy-proxy";
  version = "0.2.1";
  src = lib.cleanSource ./.;
  vendorHash = null;
  env.CGO_ENABLED = "0";
  ldflags = ["-s" "-w"];
  meta = {
    description = "Loopback Antigravity native relay and minimally adapting Gemini API";
    license = lib.licenses.mit;
    platforms = lib.platforms.unix;
    mainProgram = "agy-proxy";
  };
}
