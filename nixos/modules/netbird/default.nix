{
  config,
  lib,
  pkgs,
  ...
}: let
  httpsPort = 8443;

  rootDomain = "imdomestic.com";

  authDomain = "auth.${rootDomain}";
  netbirdDomain = "netbird.${rootDomain}";

  # 你后面在 Zitadel 创建 NetBird OIDC App 拿到的 ClientID
  netbirdClientId = "REPLACE_ME_CLIENT_ID";
in {
  #### ACME (DNS-01) - 不需要 80/443
  security.acme = {
    acceptTerms = true;
    defaults.email = "hankchogan@gmail.com";
  };
  security.acme.certs.${authDomain} = {
    dnsProvider = "cloudflare";
    credentialsFile = "/var/lib/secrets/acme/cloudflare.env";
    group = "nginx";
  };
  security.acme.certs.${netbirdDomain} = {
    dnsProvider = "cloudflare";
    credentialsFile = "/var/lib/secrets/acme/cloudflare.env";
    group = "nginx";
  };

  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    recommendedTlsSettings = true;
    recommendedGzipSettings = true;
  };

  virtualisation.podman.enable = true;
  virtualisation.oci-containers.backend = "podman";

  virtualisation.oci-containers.containers.zitadel-db = {
    image = "postgres:17";
    ports = ["127.0.0.1:5432:5432"];
    environmentFiles = ["/var/lib/secrets/zitadel/postgres_env"];
    volumes = ["/var/lib/zitadel-db:/var/lib/postgresql/data"];
  };
  system.activationScripts.makeZitadelDbDir = lib.stringAfter ["var"] ''
    mkdir -p /var/lib/zitadel-db
    chmod 700 /var/lib/zitadel-db
  '';

  services.zitadel = {
    enable = true;

    tlsMode = "external";
    masterKeyFile = "/var/lib/secrets/zitadel/master_key";
    extraStepsPaths = ["/var/lib/secrets/zitadel/admin_steps.yaml"];
    extraSettingsPaths = ["/var/lib/secrets/zitadel/settings.yaml"];

    settings = {
      Port = 39995; # Zitadel 实际监听（本机）
      ExternalPort = httpsPort;
      ExternalDomain = authDomain;
      ExternalSecure = true;

      Database.postgres = {
        Host = "127.0.0.1";
        Port = 5432;
        Database = "zitadel";
        MaxOpenConns = 15;
        MaxIdleConns = 10;
        MaxConnLifetime = "1h";
        MaxConnIdleTime = "5m";
      };
    };
  };

  services.nginx.virtualHosts.${authDomain} = {
    serverName = authDomain;
    useACMEHost = authDomain;
    forceSSL = true;

    listen = lib.mkForce [
      {
        addr = "0.0.0.0";
        port = httpsPort;
        ssl = true;
      }
      {
        addr = "[::]";
        port = httpsPort;
        ssl = true;
      }
    ];
    http2 = true;
    extraConfig = ''
      proxy_headers_hash_max_size 512;
      proxy_headers_hash_bucket_size 128;
    '';

    locations."/" = {
      proxyPass = "http://127.0.0.1:39995";
      proxyWebsockets = true;
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
      '';
    };
  };

  #### （阶段2再开启）NetBird Server + TURN + Relay + WebUI
  # imports = [ ... 你自己的 netbird 相关模块 ... ];
}
