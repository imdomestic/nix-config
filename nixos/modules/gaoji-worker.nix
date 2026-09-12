{
  config,
  inputs,
  ...
}: let
  host = config.my.host;
  hosts = import ../hosts {inherit inputs;};
  resources = (import ../../lib/gaoji-workers.nix).${host.name};
  tokenName = "gaoji/worker_token";
in {
  imports = [inputs.qq-bot.nixosModules.cluster-worker inputs.qq-bot.nixosModules.host-control];
  services.gaoji-host-control = {
    enable = true;
    hostId = host.name;
  };
  sops.secrets.${tokenName} = {
    sopsFile = ../../secrets/gaoji + "/worker-${host.name}.yaml";
    key = "worker_token";
    mode = "0400";
    restartUnits = ["gaoji-cluster-worker.service"];
  };
  services.gaoji-cluster-worker =
    resources
    // {
      enable = true;
      workerId = "${host.name}-worker";
      controlUrl = "http://${hosts.h610.tsIp}:8091";
      tokenFile = config.sops.secrets.${tokenName}.path;
      listenAddress = host.tsIp;
      publicBaseUrl = "http://${host.tsIp}:8092";
    };
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [8092];
}
