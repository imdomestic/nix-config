{
  inputs,
  pkgs,
  ...
}: {
  services.dae = {
    enable = true;
    package = pkgs.dae;
    config = builtins.readFile "${inputs.dae-config.outPath}/config.dae";
    assets = with pkgs; [v2ray-geoip v2ray-domain-list-community];
  };
}
