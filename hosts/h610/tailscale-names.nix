{
  config,
  pkgs,
  ...
}: {
  services.headplane.package = import ../../lib/tailscale-bind-package.nix {
    inherit pkgs;
    package = pkgs.headplane;
    programs = ["headplane"];
    kind = "headplane";
    tsName = config.my.host.tsName;
  };
  services.nginx.resolver = {
    addresses = ["100.100.100.100"];
    valid = "30s";
    ipv6 = false;
  };
  services.nginx.upstreams.matrix-tailnet = {
    servers."tank.inner.imdomestic.com:8008".resolve = true;
    extraConfig = "zone matrix_tailnet 64k;";
  };

  services.headscale.settings.dns.extra_records = [
    {
      name = "vex.inner.imdomestic.com";
      type = "A";
      value = "100.64.0.43";
    }
  ];
}
