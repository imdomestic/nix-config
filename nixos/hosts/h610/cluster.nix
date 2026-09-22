{
  config,
  inputs,
  lib,
  ...
}: let
  host = config.my.host;
  inventory = (import ../../../lib/mkInventory.nix {inherit inputs;}) {
    hosts = import ../. {inherit inputs;};
  };
  managed = lib.filter (entry: entry.clusterControl.enable or false) inventory;
  gaojiManagementHosts = ["h310" "h610" "tank"];
  gaojiManaged = lib.filter (entry: builtins.elem entry.name gaojiManagementHosts) managed;
  gaojiWorkers = import ../../../lib/gaoji-workers.nix;
  gaojiInventory =
    map (entry: {
      host_id = entry.name;
      label = entry.name;
      architecture = entry.system;
      site = "not-recorded";
      maintainer = "shared-infrastructure";
      permission_source = "nix-config cluster control registry";
      roles = entry.roles;
      observe = true;
      operate = builtins.elem entry.name gaojiManagementHosts;
      compute = builtins.hasAttr entry.name gaojiWorkers;
      readable_units = entry.clusterControl.readableUnits ++ entry.clusterControl.manageableUnits;
      operable_units = lib.optionals (builtins.elem entry.name gaojiManagementHosts) entry.clusterControl.manageableUnits;
    })
    managed;
in {
  imports = [../../modules/gaoji-ssh.nix];
  sops.secrets =
    lib.listToAttrs (map (name: {
      name = "gaoji/workers/${name}";
      value = {
        sopsFile = ../../../secrets/gaoji + "/worker-${name}.yaml";
        key = "worker_token";
        mode = "0400";
        restartUnits = ["gaoji-cluster-control.service"];
      };
    }) ["h310" "tank"])
    // {
      "kennethbot/cluster_control_token" = {
        sopsFile = ../../../secrets/gaoji/control.yaml;
        key = "control_token";
        mode = "0400";
        restartUnits = ["gaoji-cluster-control.service" "gaoji.service"];
      };
      "gaoji/authorization_key" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "authorization_key";
        mode = "0400";
        restartUnits = ["gaoji.service"];
      };
      "gaoji/onebot_access_token" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "onebot_access_token";
        mode = "0400";
        restartUnits = ["gaoji.service" "gaoji-napcat.service"];
      };
      "gaoji/onebot_secret" = {
        sopsFile = ../../../secrets/gaoji/account-auth.yaml;
        key = "onebot_secret";
        mode = "0400";
        restartUnits = ["gaoji.service"];
      };
      "kennethbot/worker_token" = {
        sopsFile = ../../../secrets/gaoji/worker-h610.yaml;
        key = "worker_token";
        mode = "0400";
        restartUnits = [
          "gaoji-cluster-control.service"
          "gaoji-cluster-worker.service"
        ];
      };
    };

  my.tailscale.bindServices = ["gaoji-cluster-control" "gaoji-cluster-worker"];
  services.gaoji-host-control = {
    enable = true;
    hostId = host.name;
  };
  services.gaoji-cluster-control = {
    enable = true;
    stateDirectory = "kennethbot-cluster-control";
    environmentFile = config.sops.templates."qq-deepseek-bot-postgres.env".path;
    apiTokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    listenAddress = host.tsName;
    openFirewall = true;
    firewallInterfaces = ["tailscale0"];
    inventory = gaojiInventory;
    hostControlHelpers = lib.genAttrs gaojiManagementHosts (_: "/run/current-system/sw/bin/gaoji-host-control");
    ssh = {
      enable = true;
      targets = lib.listToAttrs (map (entry: lib.nameValuePair entry.name {
        destination = "gaoji-operator@${entry.tsName}";
        port = 2224;
      }) gaojiManaged);
      knownHostsFile = "${../../../lib/gaoji-ssh-known-hosts}";
      identityFile = "/var/lib/gaoji-operations-identity/id_ed25519";
      managementHosts = gaojiManagementHosts;
      administrators = ["qq:3526452465" "admin:kenneth"];
    };
    workers = map (name: {
      workerId = "${name}-worker";
      hostId = name;
      ownerAliases = ["qq:3526452465"];
      tokenFile =
        if name == "h610"
        then config.sops.secrets."kennethbot/worker_token".path
        else config.sops.secrets."gaoji/workers/${name}".path;
    }) (builtins.attrNames gaojiWorkers);
    diagnostics.targets =
      map (entry: {
        target_id = "${entry.name}-worker";
        label = "${entry.name} gaoji Worker";
        kind = "service";
        url = "http://${entry.tsName}:8092/health";
        observer_host = "h610";
        host_id = entry.name;
        service_ref = "gaoji-cluster-worker.service";
      })
      gaojiManaged;
  };

  services.gaoji-cluster-worker = {
    enable = true;
    stateDirectory = "kennethbot-cluster-worker";
    workerId = "h610-worker";
    controlUrl = "http://${host.tsName}:${toString config.services.gaoji-cluster-control.port}";
    tokenFile = config.sops.secrets."kennethbot/worker_token".path;
    listenAddress = host.tsName;
    publicBaseUrl = "http://${host.tsName}:${toString config.services.gaoji-cluster-worker.port}";
    cpuMillis = 2000;
    memoryBytes = 2 * 1024 * 1024 * 1024;
    concurrency = 2;
  };

  services.gaoji.cluster = {
    enable = true;
    controlUrl = "http://${host.tsName}:${toString config.services.gaoji-cluster-control.port}";
    tokenFile = config.sops.secrets."kennethbot/cluster_control_token".path;
    allowedGroups = [611798505 650536599];
    logAllowedGroups = [];
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [
    config.services.gaoji-cluster-worker.port
  ];
}
