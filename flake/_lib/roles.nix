# The host roles: the one knob for what a machine is. A role either brings in
# system profiles (`profiles.<class>`, added after base by
# flake/builders/systems.nix) or is read by a module.
# `roles` is an enum of these names, so a typo fails evaluation.
{
  server = {
    description = "Headless service box: system/profiles/server.nix (ssh, telemetry, no docs; no graphics unless also `desktop`).";
    profiles.nixos = [../../system/profiles/server.nix];
  };
  desktop = {
    description = "Has a graphical session: system/profiles/desktop.nix (GNOME, pipewire, input method) on NixOS; a label on macOS.";
    profiles.nixos = [../../system/profiles/desktop.nix];
  };
  router = {
    description = "Router or gateway people debug from a shell: system/profiles/netdiag.nix.";
    profiles.nixos = [../../system/profiles/netdiag.nix];
  };
  vm-host = {
    description = "Runs VMs and containers: system/profiles/virtualisation.nix.";
    profiles.nixos = [../../system/profiles/virtualisation.nix];
  };
  gui = {
    description = "Accounts here get their GUI layers (flake/builders/homes.nix).";
  };
  monitor = {
    description = "Runs a full monitoring stack (system/modules/monitoring).";
  };
  monitor-gateway = {
    description = "Runs the Grafana entry point in front of the monitors (system/modules/monitoring/gateway.nix).";
  };
  gpu-compute = {
    description = "GPU compute box; only a monitoring label for now.";
  };
}
