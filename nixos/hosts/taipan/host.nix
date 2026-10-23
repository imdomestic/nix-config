{
  config,
  inputs,
  ...
}: let
  m = config.flake.modules;
in {
  hosts.taipan = {
    system = "x86_64-linux";
    kind = "nixos";
    roles = ["server" "gpu-compute" "desktop" "gui"];
    tsName = "taipan.inner.imdomestic.com";
    ageKey = "age1qpgrpyp6swk2a2hystwaryaulrvyrtjecmzzjlnjawsn50ckg3fqj8rsaf";
    gpuMonitoring = {
      enable = true;
      uuids = ["GPU-d8ec4dea-3771-68e6-9f8b-11811e47ac9d"];
    };

    clusterControl = {
      enable = true;
      manageableUnits = [
        "tailscaled.service"
        "prometheus-node-exporter.service"
        "llama-swap.service"
        "llama-swap-proxy.service"
        "podman-qwen38.service"
        "podman-qwen38-abliterated.service"
        "podman-clef.service"
        "nvidia-persistenced.service"
      ];
    };

    profiles = with m.nixos; [
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

    users.hank.ageKey = "age1esxjvsmcrlm7s7dks66mchddga45mdlr595u40862r649vrps4gsaxapnj";
  };
}
