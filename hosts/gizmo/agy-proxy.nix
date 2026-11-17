{
  config,
  lib,
  ...
}: let
  cfg = config.services.agy-proxy;
in {
  services.agy-proxy = {
    enable = true;
    openaiCompat = true;
    clientKeyFile = config.sops.secrets."agy-proxy/api_key".path;
    oauthClientFile = config.sops.secrets."agy-proxy/oauth_client".path;
  };
  sops.secrets."agy-proxy/api_key" = {
    sopsFile = ../../secrets/clients/agy-proxy.yaml;
    restartUnits = ["agy-proxy.service"];
  };
  sops.secrets."agy-proxy/oauth_client".restartUnits = ["agy-proxy.service"];

  # Native OAuth/control endpoints stay private; see docs/agy-proxy.md.
  services.nginx.virtualHosts.${config.my.host.tsName}.locations = {
    "^~ /agy/v1beta/" = {
      proxyPass = "http://127.0.0.1:${toString cfg.port}/v1beta/";
      extraConfig = ''
        client_max_body_size 64m;
        access_log off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-Goog-Api-Key $http_x_goog_api_key;
        proxy_set_header X-Agy-Session-Id $http_x_agy_session_id;
        proxy_set_header X-Agy-Request-Id $http_x_agy_request_id;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_connect_timeout 10s;
        gzip off;
      '';
    };
    "^~ /agy/v1/" = lib.mkIf cfg.openaiCompat {
      proxyPass = "http://127.0.0.1:${toString cfg.port}/v1/";
      extraConfig = ''
        client_max_body_size 64m;
        access_log off;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_connect_timeout 10s;
        gzip off;
      '';
    };
  };
}
