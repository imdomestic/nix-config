{
  config,
  inputs,
  ...
}: let
  host = config.my.host;
  resources = (import ../../lib/gaoji-workers.nix).${host.name};
  tokenName = "gaoji/worker_token";
in {
  imports = [inputs.qq-bot.nixosModules.cluster-worker inputs.qq-bot.nixosModules.host-control ./gaoji-ssh.nix];
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
  my.tailscale.bindServices = ["gaoji-cluster-worker"];
  services.gaoji-cluster-worker =
    resources
    // {
      enable = true;
      workerId = "${host.name}-worker";
      controlUrl = let
        p = config.my.fleet.placements.gaoji-control;
      in "http://${p.tsName}:${toString p.port}";
      tokenFile = config.sops.secrets.${tokenName}.path;
      listenAddress = host.tsName;
      publicBaseUrl = "http://${host.tsName}:8092";
    };
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [8092];
}
