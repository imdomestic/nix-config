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

  netbirdClientId = "360296295379829249";
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
      LoginV2.Required = false;

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

  services.netbird = {
    # 如果你这台机已经有 WireGuard( wg-quick wg0 )，别用默认 51820，防止冲突
    clients.default = {
      port = 51830;
      interface = "nb0";
      hardened = true;
      # 你要自动登录就用 setupKeyFile（后面 dashboard 里生成）
      # login.enable = true;
      # login.setupKeyFile = "/var/lib/secrets/netbird/setup_key";
    };

    # 你这台既当 server 又当路由/出口节点，通常选 both
    useRoutingFeatures = "both";

    server = {
      enable = true;
      enableNginx = true;
      domain = netbirdDomain;

      coturn = {
        enable = true;
        domain = netbirdDomain;
        passwordFile = "/var/lib/secrets/netbird/turn_password";
      };

      dashboard = {
        enable = true;
        enableNginx = true;
        domain = netbirdDomain;
        settings = {
          AUTH_AUTHORITY = "https://${authDomain}:${toString httpsPort}";
          AUTH_CLIENT_ID = netbirdClientId;
          AUTH_AUDIENCE = netbirdClientId;

          AUTH_REDIRECT_URI = "/auth";
          AUTH_SILENT_REDIRECT_URI = "/silent-auth";

          NETBIRD_MGMT_API_ENDPOINT = lib.mkForce "https://${netbirdDomain}:${toString httpsPort}";
          NETBIRD_MGMT_GRPC_API_ENDPOINT = lib.mkForce "https://${netbirdDomain}:${toString httpsPort}";

          AUTH_SUPPORTED_SCOPES = "openid profile email offline_access api";
          USE_AUTH0 = false;
          NETBIRD_TOKEN_SOURCE = "idToken";
        };
      };

      management = {
        enable = true;
        logLevel = "DEBUG";
        enableNginx = true;
        domain = netbirdDomain;

        turnDomain = netbirdDomain;
        singleAccountModeDomain = netbirdDomain;

        oidcConfigEndpoint = "https://${authDomain}:${toString httpsPort}/.well-known/openid-configuration";

        settings = {
          Signal.URI = "${netbirdDomain}:${toString httpsPort}";

          HttpConfig.AuthAudience = netbirdClientId;

          DeviceAuthorizationFlow.ProviderConfig = {
            UseIDToken = true;
            Audience = netbirdClientId;
            ClientID = netbirdClientId;
          };
          PKCEAuthorizationFlow.ProviderConfig = {
            UseIDToken = true;
            Audience = netbirdClientId;
            ClientID = netbirdClientId;
          };

          TURNConfig = {
            Secret._secret = "/var/lib/secrets/netbird/turn_password";
            CredentialsTTL = "12h";
            TimeBasedCredentials = false;
            Turns = [
              {
                Proto = "udp";
                URI = "turn:${netbirdDomain}:3478";
                Username = "netbird";
                Password._secret = "/var/lib/secrets/netbird/turn_password";
              }
            ];
          };

          Relay = {
            Addresses = ["rels://${netbirdDomain}:33080"];
            CredentialsTTL = "24h";
            Secret._secret = "/var/lib/secrets/netbird/relay_secret";
          };

          DataStoreEncryptionKey._secret = "/var/lib/secrets/netbird/data_store_encryption_key";
        };
      };

      signal = {
        enable = true;
        enableNginx = true;
        domain = netbirdDomain;
      };
    };
  };

  systemd.services.netbird-management.serviceConfig.EnvironmentFile = "/var/lib/secrets/netbird/setup.env";

  services.nginx.virtualHosts.${netbirdDomain} = lib.mkMerge [
    {
      useACMEHost = netbirdDomain;
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
      locations."/" = {
        root = config.services.netbird.server.dashboard.finalDrv;

        tryFiles = lib.mkForce "$uri $uri/ /index.html";
      };
    }
  ];

  virtualisation.oci-containers.containers.netbird-relay = {
    image = "netbirdio/relay:latest";
    ports = [
      "33080:33080/tcp"
      "33080:33080/udp"
    ];
    volumes = [
      "/var/lib/acme/${netbirdDomain}/:/certs:ro"
    ];
    environment = {
      NB_LOG_LEVEL = "info";
      NB_LISTEN_ADDRESS = ":33080";
      NB_EXPOSED_ADDRESS = "rels://${netbirdDomain}:33080";
      NB_TLS_CERT_FILE = "/certs/fullchain.pem";
      NB_TLS_KEY_FILE = "/certs/key.pem";
    };
    environmentFiles = [
      "/var/lib/secrets/netbird/relay_secret_container"
    ];
  };

  # virtualisation.oci-containers.containers.zitadel-login = {
  #   image = "ghcr.io/zitadel/zitadel-login:latest";
  #   ports = ["127.0.0.1:3000:3000"];
  #
  #   environment = {
  #     ZITADEL_API_URL = "http://127.0.0.1:39995"; # 你 zitadel 内部端口
  #     NEXT_PUBLIC_BASE_PATH = "/ui/v2/login";
  #     ZITADEL_SERVICE_USER_TOKEN_FILE = "/secrets/login-client.pat";
  #     CUSTOM_REQUEST_HEADERS = "Host:${authDomain}";
  #   };
  #
  #   volumes = [
  #     "/var/lib/secrets/zitadel/login-client.pat:/secrets/login-client.pat:ro"
  #   ];
  # };
  # services.nginx.virtualHosts.${authDomain}.locations."/ui/v2/login" = {
  #   proxyPass = "http://127.0.0.1:3000";
  #   extraConfig = ''
  #     proxy_set_header Host $host;
  #     proxy_set_header X-Forwarded-Proto https;
  #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  #   '';
  # };

  services.coturn = {
    min-port = 40000;
    max-port = 40050;
  };
}
