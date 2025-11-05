{ inputs, pkgs, ... }:

{
  services.mihomo = {
    enable = true;
    tunMode = true;
    webui = pkgs.metacubexd;
    configFile = "${inputs.mihomo-config.outPath}/config.yaml";
  };
}
