# The Rust rewrite of Max, running beside the Haskell max as a separate
# stack: its own user, database, directories and units, all named maxx.
# Design: docs/rust-rewrite.md on the max repo's maxx branch. It reaches QQ
# through Tencent's official bot API, as the bot maxx.
{
  config,
  lib,
  ...
}: let
  secretNames = ["qq-app-id" "qq-app-secret"];
in {
  sops.secrets = lib.genAttrs (map (name: "maxx/${name}") secretNames) (_: {
    sopsFile = ../../secrets/hosts/tank-max.yaml;
    owner = "maxx";
    restartUnits = ["maxx.service"];
  });

  services.maxx = {
    enable = true;
    settings.platforms.qq = {
      app_id_file = config.sops.secrets."maxx/qq-app-id".path;
      app_secret_file = config.sops.secrets."maxx/qq-app-secret".path;
    };
  };
}
