# HTTPS in front of the NInfer gateway, for clients that refuse a non-local
# http base_url (fx). The plain http endpoint on :8000 stays as it is.
{
  config,
  lib,
  pkgs,
  ...
}: let
  domain = config.my.host.tsName;
  cfg = config.services.qwen38Ninfer;
  # The gateway binds the tailnet IPv4 address only, which is what the name resolves to here.
  upstream = "http://${domain}:${toString cfg.gatewayPort}";
  orderUnit = "acme-order-renew-${domain}.service";
  verifyCertificate = pkgs.writeShellScript "ninfer-https-certificate-ready" ''
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
      assertion = cfg.enable;
      message = "NInfer HTTPS requires services.qwen38Ninfer.";
    }
  ];

  sops.secrets."ddns/cloudflare_token" = {};
  sops.templates."ninfer-acme.env" = {
    content = ''
      CF_DNS_API_TOKEN=${config.sops.placeholder."ddns/cloudflare_token"}
    '';
    restartUnits = [orderUnit];
  };

  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
    certs.${domain} = {
      dnsProvider = "cloudflare";
      # MagicDNS does not answer public SOA queries; see docs/incidents.md#gaoji-acme-inner-soa.
      dnsResolver = "1.1.1.1:53";
      environmentFile = config.sops.templates."ninfer-acme.env".path;
      extraLegoFlags = ["--dns.propagation-wait" "120s"];
      group = "nginx";
    };
  };

  my.tailscale.bindServices = ["nginx"];
  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [443];

  # Wait for DNS-01 issuance and reject ACME's temporary self-signed certificate.
  systemd.services.nginx = {
    # Native nginx orders itself before ACME for HTTP-01; DNS-01 needs the opposite.
    before = lib.mkForce [];
    after = [orderUnit "llama-swap-proxy.service"];
    wants = [orderUnit];
    serviceConfig.ExecStartPre = [verifyCertificate];
  };

  services.nginx = {
    enable = true;
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
            client_max_body_size 64m;
            gzip off;
          '';
        };
      };
    };
  };
}
