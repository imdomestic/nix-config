# The host roles: the one knob for what a machine is. A role either brings in
# system profiles (`profiles.<class>`, names in `flake.modules.<class>`, added
# after base by flake/builders/systems.nix) or is read by a module.
# `roles` is an enum of these names, so a typo fails evaluation.
{
  server = {
    description = "Headless service box: nixos/profiles/server.nix (ssh, telemetry, no docs; no graphics unless also `desktop`).";
    profiles.nixos = ["server"];
  };
  desktop = {
    description = "Has a graphical session: nixos/profiles/desktop.nix (GNOME, pipewire, input method) on NixOS; a label on macOS.";
    profiles.nixos = ["desktop"];
  };
  router = {
    description = "Router or gateway people debug from a shell: nixos/profiles/netdiag.nix.";
    profiles.nixos = ["netdiag"];
  };
  vm-host = {
    description = "Runs VMs and containers: nixos/profiles/virtualisation.nix.";
    profiles.nixos = ["virtualisation"];
  };
  gui = {
    description = "Accounts here get their GUI layers (flake/builders/homes.nix).";
  };
  monitor = {
    description = "Runs a full monitoring stack (nixos/modules/monitoring).";
  };
  monitor-gateway = {
    description = "Runs the Grafana entry point in front of the monitors (nixos/modules/monitoring/gateway.nix).";
  };
  gpu-compute = {
    description = "GPU compute box; only a monitoring label for now.";
  };
}
