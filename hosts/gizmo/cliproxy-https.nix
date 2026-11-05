{
  config,
  lib,
  pkgs,
  ...
}: let
  domain = config.my.host.tsName;
  upstream = "http://${config.services.cliproxy.bindAddress}:${toString config.services.cliproxy.port}";
  orderUnit = "acme-order-renew-${domain}.service";
  verifyCertificate = pkgs.writeShellScript "cliproxy-https-certificate-ready" ''
    set -eu
    ${pkgs.openssl}/bin/openssl verify \
      -CAfile ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt \
      -untrusted /var/lib/acme/${domain}/chain.pem \
      /var/lib/acme/${domain}/cert.pem
    ${pkgs.openssl}/bin/openssl x509 \
      -in /var/lib/acme/${domain}/cert.pem -noout -checkhost ${lib.escapeShellArg domain}
  '';
in {
  assertions = [
    {
      assertion = config.services.cliproxy.enable && config.services.cliproxy.bindAddress == domain;
      message = "CLIProxy HTTPS requires its HTTP upstream on this host's Tailscale address.";
    }
  ];

  sops.templates."cliproxy-acme.env" = {
    content = ''
      CF_DNS_API_TOKEN=${config.sops.placeholder."ddns/cloudflare_token"}
    '';
    restartUnits = [orderUnit];
  };

  security.acme.certs.${domain} = {
    dnsProvider = "cloudflare";
    # MagicDNS does not answer public SOA queries; see docs/incidents.md#gaoji-acme-inner-soa.
    dnsResolver = "1.1.1.1:53";
    environmentFile = config.sops.templates."cliproxy-acme.env".path;
    extraLegoFlags = ["--dns.propagation-wait" "120s"];
    group = "nginx";
  };

  my.tailscale.bindServices = ["nginx"];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [443];

  # Wait for DNS-01 issuance and reject ACME's temporary self-signed certificate.
  systemd.services.nginx = {
    # Native nginx orders itself before ACME for HTTP-01; DNS-01 needs the opposite.
    before = lib.mkForce [];
    after = [orderUnit];
    wants = [orderUnit];
    serviceConfig.ExecStartPre = [verifyCertificate];
  };

  services.nginx = {
    recommendedTlsSettings = true;
    virtualHosts.${domain} = {
      useACMEHost = domain;
      onlySSL = true;
      listen = [
        {
          addr = domain;
          port = 443;
          ssl = true;
        }
      ];
      locations = {
        # Only the model API is exposed; management stays on the original HTTP endpoint.
        "/".return = "404";
        "^~ /v1/" = {
          proxyPass = upstream;
          proxyWebsockets = true;
          extraConfig = ''
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Authorization $http_authorization;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_connect_timeout 10s;
            gzip off;
          '';
        };
      };
    };
  };
}
