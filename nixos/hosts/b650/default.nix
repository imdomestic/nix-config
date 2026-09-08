{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server" "gpu-compute"];
  tsIp = "100.64.0.33";

  maxops = {
    enable = true;
    manageableUnits = [
      "maxops-agent.service"
      "maxops-executor.service"
      "tailscaled.service"
      "prometheus-node-exporter.service"
      "llama-swap.service"
      "llama-swap-proxy.service"
      "podman-qwen38.service"
      "podman-qwen38-long.service"
      "nvidia-persistenced.service"
    ];
  };

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    inputs.nix-index-database.nixosModules.default
  ];

  users.hank.home = {
    profiles = with homeProfiles; [
      core
      base
    ];
    modules = [
      userModules.hank.module
      userModules.hank.dev
    ];
  };
}
