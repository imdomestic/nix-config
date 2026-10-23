# ddns-go keeping this host's Cloudflare records on its current public
# addresses. Imported by nixos/profiles/base.nix and off by default; a host turns
# it on with `my.ddns.enable` and describes its zones. The defaults are the
# common router shape: IPv6 from ppp0 for <host>:imdomestic.com, IPv4 off.
{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkOption types;
  cfg = config.my.ddns;

  ipv4Urls = "https://myip.ipip.net, https://ddns.oray.com/checkip, https://ip.3322.net, https://4.ipw.cn, https://v4.yinghualuo.cn/bejson";
  ipv6Urls = "https://speed.neu6.edu.cn/getIP.php, https://v6.ident.me, https://6.ipw.cn, https://v6.yinghualuo.cn/bejson";

  zoneType = types.submodule {
    options = {
      name = mkOption {
        type = types.str;
        default = "";
        description = "Label of this entry in ddns-go.";
      };
      tokenSecret = mkOption {
        type = types.str;
        default = "ddns/cloudflare_token";
        description = "sops secret holding the Cloudflare API token for this zone.";
      };
      ipv4 = {
        enable = lib.mkEnableOption "updating A records";
        interface = mkOption {
          type = types.str;
          default = "wan0";
          description = "Interface the IPv4 address is read from.";
        };
        domains = mkOption {
          type = types.listOf types.str;
          default = [];
          description = "Records to keep on the IPv4 address (ddns-go syntax, e.g. `h610:imdomestic.com`).";
        };
      };
      ipv6 = {
        interface = mkOption {
          type = types.str;
          default = "ppp0";
          description = "Interface the IPv6 address is read from.";
        };
        regex = mkOption {
          type = types.str;
          default = "";
          example = "@2";
          description = "ddns-go's ipv6reg: which of the interface's addresses to use.";
        };
        domains = mkOption {
          type = types.listOf types.str;
          default = ["${config.my.host.name}:imdomestic.com"];
          defaultText = lib.literalExpression ''["''${config.my.host.name}:imdomestic.com"]'';
          description = "Records to keep on the IPv6 address.";
        };
      };
    };
  };

  # Zones are rendered with `- name` at column 0, then shifted under dnsconf.
  indent = text: lib.concatMapStrings (l: "    ${l}\n") (lib.init (lib.splitString "\n" text));
  domainList = ds:
    lib.concatMapStrings (d: "\n        - ${d}") (
      if ds == []
      then [''""'']
      else ds
    );
  zoneYaml = z: let
    gettype4 =
      if z.ipv4.enable
      then "netInterface"
      else "url";
    reg =
      if z.ipv6.regex == ""
      then ''""''
      else "'${z.ipv6.regex}'";
  in
    indent ''
      - name: "${z.name}"
        ipv4:
          enable: ${lib.boolToString z.ipv4.enable}
          gettype: ${gettype4}
          url: ${ipv4Urls}
          netinterface: ${z.ipv4.interface}
          cmd: ""
          domains:${domainList z.ipv4.domains}
        ipv6:
          enable: true
          gettype: netInterface
          url: ${ipv6Urls}
          netinterface: ${z.ipv6.interface}
          cmd: ""
          ipv6reg: ${reg}
          domains:${domainList z.ipv6.domains}
        dns:
          name: cloudflare
          id: ""
          secret: ${config.sops.placeholder.${z.tokenSecret}}
        ttl: ""
    '';
in {
  options.my.ddns = {
    enable = lib.mkEnableOption "ddns-go updating this host's Cloudflare records";
    zones = mkOption {
      type = types.listOf zoneType;
      default = [{}];
      description = "One entry per Cloudflare zone (each has its own token).";
    };
    user = mkOption {
      type = types.str;
      default = "hank";
      description = "Login of ddns-go's web UI.";
    };
    passwordSecret = mkOption {
      type = types.str;
      default = "ddns/web_password";
      description = "sops secret holding the web UI password.";
    };
  };

  config = lib.mkIf cfg.enable {
    sops.secrets = lib.genAttrs (lib.unique (map (z: z.tokenSecret) cfg.zones ++ [cfg.passwordSecret])) (_: {});

    sops.templates."ddns-go-config.yaml" = {
      restartUnits = ["ddns-go.service"];
      content =
        "dnsconf:\n"
        + lib.concatMapStrings zoneYaml cfg.zones
        + ''
          user:
              username: ${cfg.user}
              password: ${config.sops.placeholder.${cfg.passwordSecret}}
          webhook:
              webhookurl: ""
              webhookrequestbody: ""
              webhookheaders: ""
          notallowwanaccess: false
          lang: zh
        '';
    };

    # web 界面(9876)监听所有地址;只给 tailnet。路由器上 LAN 本来就是信任网卡。
    networking.firewall.interfaces.tailscale0.allowedTCPPorts = [9876];

    systemd.services.ddns-go = {
      enable = true;
      description = "ddns-go";

      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = ["network-online.target"];

      serviceConfig = {
        ExecStart = "${pkgs.ddns-go.outPath}/bin/ddns-go -f 300 -c ${config.sops.templates."ddns-go-config.yaml".path}";
        Restart = "always";
        RestartSec = 5;
      };
    };
  };
}
