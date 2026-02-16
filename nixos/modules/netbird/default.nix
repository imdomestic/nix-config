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

  netbirdClientId = "REPLACE_ME_CLIENT_ID";
in {
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
      extraConfig = ''
        grpc_pass grpc://127.0.0.1:39995;

        grpc_set_header Host $http_host;
        grpc_set_header X-Forwarded-Host $http_host;
        grpc_set_header X-Forwarded-Port $server_port;
        grpc_set_header X-Forwarded-Proto https;

        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
      '';
    };
  };
}
