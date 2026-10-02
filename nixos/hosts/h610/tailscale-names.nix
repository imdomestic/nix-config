{
  config,
  lib,
  pkgs,
  ...
}: let
  recordsPath = "/var/lib/headscale/dns-records.json";
  updateRecords = pkgs.writeShellApplication {
    name = "headscale-local-dns-records";
    runtimeInputs = [pkgs.tailscale pkgs.jq pkgs.coreutils];
    text = ''
      # Gaoji is an independent node; never attach service aliases to this host.
      address=$(tailscale status --json | jq -er '
        [.Peer[] | select(.DNSName == "gaoji.inner.imdomestic.com.")
          | .TailscaleIPs[] | select(startswith("100."))] | unique
        | if length == 1 then .[0] else error("Gaoji node address unavailable") end
      ')
      tmp=$(mktemp ${recordsPath}.XXXXXX)
      trap 'rm -f "$tmp"' EXIT
      jq -n --arg address "$address" '[
        {name:"kennethbot.inner.imdomestic.com", type:"A", value:$address}
      ]' > "$tmp"
      chmod 0644 "$tmp"
      if ! cmp -s "$tmp" ${recordsPath}; then
        # Headscale reattaches its watcher after an atomic replacement.
        mv "$tmp" ${recordsPath}
      fi
    '';
  };
in {
  services.headplane.package = import ../../../lib/tailscale-bind-package.nix {
    inherit pkgs;
    package = pkgs.headplane;
    programs = ["headplane"];
    kind = "headplane";
    tsName = config.my.host.tsName;
  };
  # Public Headscale on 8443 must start before the local Tailscale client.
  # Only the private HTTP/HTTPS ports use this independent input guard.
  my.tailscale.guardedTCPServices.nginx = [80 443];
  services.nginx.resolver = {
    addresses = ["100.100.100.100"];
    valid = "30s";
    ipv6 = false;
  };
  services.nginx.upstreams.matrix-tailnet = {
    servers."tank.inner.imdomestic.com:8008".resolve = true;
    extraConfig = "zone matrix_tailnet 64k;";
  };

  # Headscale extra records support literal addresses, so derive aliases at runtime.
  services.headscale.settings.dns.extra_records_path = recordsPath;
  # A scoped DNS deployment can precede the next full h610 switch.
  system.activationScripts.gaojiDNSMigration = {
    deps = ["etc"];
    text = ''
      rm -f /etc/systemd/system.control/headscale-local-dns.service.d/50-gaoji-migration.conf
      rm -f /nix/var/nix/gcroots/gaoji-dns-updater
    '';
  };
  systemd.services.headscale.preStart = lib.mkBefore ''
    if [ ! -e ${recordsPath} ]; then
      printf '[]\n' > ${recordsPath}
      chmod 0644 ${recordsPath}
    fi
  '';
  systemd.services.headscale-local-dns = {
    after = ["headscale.service" "tailscaled.service"];
    requires = ["headscale.service"];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe updateRecords;
    };
  };
  systemd.timers.headscale-local-dns = {
    wantedBy = ["timers.target"];
    timerConfig = {
      OnBootSec = "30s";
      OnUnitActiveSec = "30s";
    };
  };
}
