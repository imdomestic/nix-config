{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  roles = ["server" "gpu-compute" "desktop" "gui"];
  tsIp = "100.64.0.33";
  gpuMonitoring = {
    enable = true;
    uuids = ["GPU-d8ec4dea-3771-68e6-9f8b-11811e47ac9d"];
  };

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
    ./desktop.nix
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
      ../../../home/users/hank/gnome.nix
    ];
  };
}
