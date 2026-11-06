# A PPPoE router's data plane: boot the host's real configuration between a
# simulated ISP and a LAN client, and check what the smoke test cannot see —
# that it dials with its sops login, gets a delegated prefix, hands the LAN
# addresses, forwards with clamped MSS, and shows the WAN only what its
# firewall allows. Why: docs/decisions.md#router-tests.
{
  pkgs,
  lib,
  systemModules,
  nixos,
  vmify,
  testSecrets,
}: {
  hostName,
  # The host's NIC names, so its networkd and pppd configuration apply as is.
  wan,
  lan,
  # services.pppd.peers.<peer>; its login is the sops secret pppoe/<peer>.
  peer,
  mss ? {
    v4 = 1452;
    v6 = 1432;
  },
  # A LAN machine the WAN side can reach is a hole; a host that has one says
  # why here, and the test then fails once it is closed, so this goes too.
  lanReachableFromWan ? null,
  memory ? 4096,
}: let
  sm = systemModules {
    inherit hostName;
    withHardware = false;
  };
  login = {
    user = "fleet-test";
    password = "fleet-test-password";
  };
  # Documentation and well-known addresses the ISP answers on: 223.5.5.5 and
  # 2400:3200::1 are AliDNS, which dae sends direct; the PPPoE link is
  # 203.0.113.1 <-> .2; the ISP delegates /60s out of 2001:db8:100::/56.
  isp4 = "203.0.113.1";
  router4 = "203.0.113.2";
  domestic4 = "223.5.5.5";
  domestic6 = "2400:3200::1";
  delegated = "2001:db8:100::";
  # How an address out of it starts, e.g. 2001:db8:100:0:c818:...
  delegatedIn = "2001:db8:100:";
  wanNet6 = "2001:db8:0:1::";
  # One node for each of dae's groups (im, au) so its configuration parses;
  # nothing listens behind them.
  daeNodes = ''
    imdomestic-fleet-test: 'socks5://198.51.100.9:1080'
    au-fleet-test: 'socks5://198.51.100.9:1081'
  '';

  web = port: dir: {
    wantedBy = ["multi-user.target"];
    after = ["network.target"];
    serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server ${toString port} --bind :: --directory ${dir}";
  };
  page = text: pkgs.writeTextDir "index.html" text;

  ipv6Up = pkgs.writeShellScript "ipv6-up" ''
    # pppd runs this when IPv6CP is up ($1 the interface, $4 our link-local
    # address): route the WAN /64 and the delegated prefixes to the router,
    # and start answering it now that $1 exists. pppd sets the link-local
    # address with a peer, which Kea reads as the peer's and fails to bind;
    # a plain one works.
    ${pkgs.iproute2}/bin/ip -6 addr flush dev "$1" scope link
    ${pkgs.iproute2}/bin/ip -6 addr add "$4/64" dev "$1"
    ${pkgs.iproute2}/bin/ip -6 route replace ${wanNet6}/64 dev "$1"
    ${pkgs.iproute2}/bin/ip -6 route replace ${delegated}/56 dev "$1"
    ${pkgs.systemd}/bin/systemctl restart kea-dhcp6-server.service radvd.service
  '';
in
  pkgs.testers.runNixOSTest {
    name = "router-${hostName}";
    node.specialArgs = sm.specialArgs;
    node.pkgsReadOnly = false;

    nodes.isp = {pkgs, ...}: {
      virtualisation.interfaces.eth1 = {
        vlan = 1;
        assignIP = false;
      };
      networking.useDHCP = false;
      networking.firewall.enable = false;
      # The "internet": addresses the ISP itself answers on. (Scripted
      # networking leaves lo alone, so networking.interfaces.lo does not.)
      systemd.services.isp-addresses = {
        wantedBy = ["multi-user.target"];
        before = ["isp-web.service"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          ${pkgs.iproute2}/bin/ip addr replace ${domestic4}/32 dev lo
          ${pkgs.iproute2}/bin/ip -6 addr replace ${domestic6}/128 dev lo
        '';
      };
      # radvd refuses to run on a host that does not forward.
      boot.kernel.sysctl."net.ipv6.conf.all.forwarding" = 1;
      environment.systemPackages = with pkgs; [tcpdump netcat-openbsd curl];

      systemd.services.pppoe-server = {
        wantedBy = ["multi-user.target"];
        after = ["network.target"];
        # eth1 has no addresses, so nothing else brings it up.
        serviceConfig.ExecStartPre = "${pkgs.iproute2}/bin/ip link set eth1 up";
        serviceConfig.ExecStart = "${pkgs.rp-pppoe}/sbin/pppoe-server -F -O /etc/ppp/pppoe-server-options -q ${pkgs.ppp}/sbin/pppd -I eth1 -L ${isp4} -R ${router4} -N 1";
      };
      environment.etc = {
        "ppp/pppoe-server-options".text = ''
          plugin pppoe.so
          require-pap
          +ipv6
          lcp-echo-interval 10
          lcp-echo-failure 2
          nobsdcomp
          noccp
          novj
        '';
        "ppp/pap-secrets" = {
          text = ''"${login.user}" * "${login.password}" *'';
          mode = "0600";
        };
        "ppp/ipv6-up".source = ipv6Up;
      };

      services.kea.dhcp6 = {
        enable = true;
        settings = {
          interfaces-config = {
            interfaces = ["ppp0"];
            service-sockets-require-all = false;
          };
          lease-database = {
            type = "memfile";
            persist = false;
          };
          subnet6 = [
            {
              id = 1;
              subnet = "${wanNet6}/64";
              interface = "ppp0";
              pools = [{pool = "${wanNet6}100 - ${wanNet6}1ff";}];
              pd-pools = [
                {
                  prefix = delegated;
                  prefix-len = 56;
                  delegated-len = 60;
                }
              ];
            }
          ];
        };
      };
      # Kea refuses a subnet on an interface that does not exist yet;
      # ipv6-up starts it once the session is up.
      systemd.services.kea-dhcp6-server.wantedBy = lib.mkForce [];
      services.radvd = {
        enable = true;
        config = ''
          interface ppp0 {
            AdvSendAdvert on;
            IgnoreIfMissing on;
            MinRtrAdvInterval 3;
            MaxRtrAdvInterval 10;
            AdvManagedFlag on;
            AdvOtherConfigFlag on;
          };
        '';
      };
      systemd.services.isp-web = web 80 (page "isp-ok");
    };

    nodes.router = {
      imports =
        sm.modules
        ++ [
          (vmify {
            inherit hostName;
            inherit (nixos.${hostName}.pkgs.stdenv.hostPlatform) system;
            secrets = testSecrets hostName {
              "pppoe/${peer}" = ''
                user "${login.user}"
                password "${login.password}"
              '';
              "dae/nodes" = daeNodes;
            };
          })
        ];
      virtualisation = {
        memorySize = memory;
        cores = 4;
        diskSize = 8192;
        interfaces = {
          ${wan} = {
            vlan = 1;
            assignIP = false;
          };
          ${lan} = {
            vlan = 2;
            assignIP = false;
          };
        };
      };
    };

    nodes.lan = {pkgs, ...}: {
      virtualisation.interfaces.eth1 = {
        vlan = 2;
        assignIP = false;
      };
      networking.useDHCP = false;
      networking.useNetworkd = true;
      # Only the router's filtering is under test.
      networking.firewall.enable = false;
      services.resolved.enable = true;
      systemd.network.networks."10-lan" = {
        matchConfig.Name = "eth1";
        networkConfig = {
          DHCP = "ipv4";
          IPv6AcceptRA = true;
        };
      };
      environment.systemPackages = [pkgs.curl];
      systemd.services.lan-web = web 8080 (page "lan-ok");
    };

    testScript = {nodes, ...}: let
      fw = nodes.router.networking.firewall;
      tcp = c: c.allowedTCPPorts ++ lib.concatMap (r: lib.range r.from r.to) c.allowedTCPPortRanges;
      proxyUnits =
        lib.optional (nodes.router.services.dae.enable or false) "dae.service"
        ++ lib.optional (nodes.router.services.mihomo.enable or false) "mihomo.service";
      openOnWan = lib.unique (tcp fw ++ lib.optionals (fw.interfaces ? ppp0) (tcp fw.interfaces.ppp0));
    in ''
      import json

      def addr(machine, dev, family, scope=""):
          """The first address on dev, or "" if it has none."""
          out = machine.succeed(f"ip -{family} -o addr show dev {dev} {scope} | awk '{{print $4}}' | cut -d/ -f1")
          return (out.split() or [""])[0]

      def syn(target, run):
          """Capture the first SYN to target:80 on the ISP's side of the link.
          Not just target: dae sends its own DNS to AliDNS, i.e. to 223.5.5.5.
          tcp[] only looks into IPv4; in IPv6 the flags are byte 40 + 13."""
          flags = "ip6[53] & 2 != 0" if ":" in target else "tcp[tcpflags] & tcp-syn != 0"
          isp.succeed("rm -f /tmp/syn && systemd-run sh -c "
                      f"\"${pkgs.tcpdump}/bin/tcpdump -lvni ppp0 -c 1 '{flags} and dst host {target} and dst port 80' > /tmp/syn 2>&1\"")
          isp.sleep(2)
          run()
          isp.wait_until_succeeds("grep -q mss /tmp/syn", timeout=30)
          return isp.succeed("cat /tmp/syn")

      start_all()
      for m in [isp, lan]:
          m.wait_for_unit("multi-user.target")

      with subtest("PPPoE dials with the login from sops"):
          router.wait_until_succeeds("ip -4 addr show dev ppp0 | grep -q 'inet ${router4} '", timeout=300)
          isp.succeed("journalctl -b | grep -qE 'authentication succeeded for ${login.user}|user ${login.user} logged in'")

      # Not multi-user.target: a host may have boot jobs that never finish in
      # a VM. These are the ones still pending once the router has dialed.
      print(router.succeed("systemctl list-jobs --no-pager"))

      with subtest("the delegated prefix reaches br-lan"):
          router.wait_until_succeeds("ip -6 -o addr show dev br-lan scope global | grep -q ' ${delegatedIn}'", timeout=180)

      with subtest("the LAN gets DHCPv4, SLAAC, a default route and the router as DNS"):
          gw = addr(router, "br-lan", 4)
          assert gw, "br-lan has no IPv4 address"
          lan.wait_until_succeeds(f"ip -4 route show default | grep -q 'via {gw} '", timeout=120)
          lan.wait_until_succeeds("ip -6 -o addr show dev eth1 scope global | grep -q ' ${delegatedIn}'", timeout=120)
          lan.wait_until_succeeds("ip -6 route show default | grep -q via", timeout=60)
          lan.succeed(f"resolvectl dns eth1 | grep -qw {gw}")

      with subtest("the LAN reaches the internet, forwarded with MSS clamped"):
          # A transparent proxy attaches to br-lan and ppp0 late in boot, and a
          # connection open at that moment is lost.
          for unit in json.loads('${builtins.toJSON proxyUnits}'):
              router.wait_for_unit(unit)
          out = syn("${domestic4}", lambda: lan.succeed("curl -sf -m 10 http://${domestic4}/ | grep -q isp-ok"))
          print(out)
          # TTL 63: the kernel forwarded it (and the clamp applied); 64 would be
          # a connection the router made itself, e.g. through dae.
          assert "ttl 63" in out and "${router4}." in out and "mss ${toString mss.v4}" in out, out
          out = syn("${domestic6}", lambda: lan.succeed("curl -sf -m 10 'http://[${domestic6}]/' | grep -q isp-ok"))
          print(out)
          assert "hlim 63" in out and "mss ${toString mss.v6}" in out, out

      with subtest("the WAN reaches only the ports the firewall opens on it"):
          listening = sorted({int(l.rsplit(":", 1)[1]) for l in router.succeed("ss -Htln | awk '{print $4}'").split()})
          wan6 = addr(router, "ppp0", 6, "scope global")
          allowed = set(json.loads('${builtins.toJSON openOnWan}'))
          for target in ["${router4}"] + ([wan6] if wan6 else []):
              reachable = [p for p in listening if isp.execute(f"nc -z -w 2 {target} {p}")[0] == 0]
              print(f"{target}: listening {listening}, reachable {reachable}")
              unexpected = sorted(set(reachable) - allowed)
              assert not unexpected, f"reachable from the WAN on {target} but not opened on it: {unexpected}"

      with subtest("the WAN cannot reach a LAN machine"):
          lan4, lan6 = addr(lan, "eth1", 4), addr(lan, "eth1", 6, "scope global")
          # Anyone one hop upstream can route the LAN's private range at us.
          isp.succeed(f"ip route replace {lan4}/32 dev ppp0")
          reached = [a for a, url in [(lan4, f"http://{lan4}:8080/"), (lan6, f"http://[{lan6}]:8080/")]
                     if isp.execute(f"curl -sf -m 5 '{url}' | grep -q lan-ok")[0] == 0]
          print(f"LAN addresses the WAN reaches: {reached}")
          ${
        if lanReachableFromWan == null
        then ''assert not reached, f"the WAN reaches the LAN at {reached}"''
        else ''assert reached, "the WAN no longer reaches the LAN: drop lanReachableFromWan (${lanReachableFromWan})"''
      }
    '';
  }
