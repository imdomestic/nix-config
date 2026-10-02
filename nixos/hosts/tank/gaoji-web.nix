{config, lib, pkgs, ...}: let
  bot = config.services.gaoji;
  domain = "gaoji.inner.imdomestic.com";
  legacyDomain = "kennethbot.inner.imdomestic.com";
  containerName = "gaoji-web";
  hostInterface = "ve-${containerName}";
  containerAddress = "10.233.0.2";
in {
  sops.templates."gaoji-web-acme.env" = {
    content = ''
      CF_DNS_API_TOKEN=${config.sops.placeholder."ddns/cloudflare_token_imdomestic"}
    '';
    restartUnits = ["container@${containerName}.service"];
  };

  networking.nat = {
    enable = true;
    externalInterface = "br-lan";
    internalInterfaces = [hostInterface];
  };
  services.gaoji.environment.FORWARDED_ALLOW_IPS = lib.mkForce "100.64.0.3,${bot.host}";

  # A local socket avoids a Tailscale hairpin back into the host node.
  systemd.sockets.gaoji-web-upstream = {
    wantedBy = ["sockets.target"];
    listenStreams = ["/run/gaoji-web-upstream/http.sock"];
    socketConfig = {
      SocketMode = "0666";
      DirectoryMode = "0755";
      RemoveOnStop = true;
    };
  };
  systemd.services.gaoji-web-upstream = {
    serviceConfig = {
      ExecStart = "${pkgs.systemd}/lib/systemd/systemd-socket-proxyd ${bot.host}:${toString bot.port}";
      DynamicUser = true;
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
    };
  };
  systemd.services."container@${containerName}" = {
    requires = ["gaoji-web-upstream.socket"];
    after = ["gaoji-web-upstream.socket"];
    # First DNS-01 issuance waits at least 120 seconds for propagation.
    serviceConfig.TimeoutStartSec = lib.mkForce "5min";
  };

  containers.${containerName} = {
    autoStart = true;
    privateNetwork = true;
    enableTun = true;
    hostAddress = "10.233.0.1";
    localAddress = containerAddress;
    bindMounts."/run/gaoji-acme.env" = {
      hostPath = config.sops.templates."gaoji-web-acme.env".path;
      isReadOnly = true;
    };
    bindMounts."/run/gaoji-web-upstream" = {
      hostPath = "/run/gaoji-web-upstream";
      isReadOnly = true;
    };
    config = {
      system.stateVersion = "26.05";
      networking = {
        hostName = "gaoji";
        useHostResolvConf = false;
        nameservers = ["1.1.1.1" "8.8.8.8"];
        firewall.interfaces.tailscale0.allowedTCPPorts = [80 443];
      };
      services.tailscale = {
        enable = true;
        openFirewall = true;
        useRoutingFeatures = "client";
        disableTaildrop = true;
      };
      # Enrollment is one-time; /var/lib/tailscale persists in this container.
      environment.systemPackages = [pkgs.curl];
      security.acme = {
        acceptTerms = true;
        defaults.email = "hankchogan@gmail.com";
        certs.${domain} = {
          dnsProvider = "cloudflare";
          dnsResolver = "1.1.1.1:53";
          environmentFile = "/run/gaoji-acme.env";
          extraLegoFlags = ["--dns.propagation-wait" "120s"];
          extraDomainNames = [legacyDomain];
          group = "nginx";
          reloadServices = ["nginx.service"];
        };
      };
      services.nginx = {
        enable = true;
        recommendedTlsSettings = true;
        recommendedOptimisation = true;
        recommendedProxySettings = true;
        clientMaxBodySize = "0";
        virtualHosts = {
          ${domain} = {
            useACMEHost = domain;
            forceSSL = true;
            locations."/" = {
              proxyPass = "http://unix:/run/gaoji-web-upstream/http.sock:";
              proxyWebsockets = true;
              extraConfig = ''
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_buffering off;
                proxy_read_timeout 3600s;
              '';
            };
          };
          ${legacyDomain} = {
            useACMEHost = domain;
            forceSSL = true;
            locations."/".return = "308 https://${domain}$request_uri";
          };
        };
      };
    };
  };
}
