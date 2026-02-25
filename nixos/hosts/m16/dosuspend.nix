{
  config,
  pkgs,
  ...
}: let
  stateDir = "/var/lib/dosuspend";
  flagFile = "${stateDir}/enabled";

  dosuspend = pkgs.writeShellScriptBin "dosuspend" ''
    set -euo pipefail

    UNIT="no-suspend-inhibit.service"
    FLAG="${flagFile}"

    usage() {
      echo "Usage: sudo dosuspend true|false|status"
      echo "  true   : 永不 suspend/hibernate（创建开关文件并启动服务）"
      echo "  false  : 恢复允许 suspend/hibernate（删除开关文件并停止服务）"
      echo "  status : 查看当前状态"
    }

    need_root() {
      if [ "''${EUID:-$(id -u)}" -ne 0 ]; then
        echo "This command needs root. Please run with sudo."
        exit 1
      fi
    }

    cmd="''${1:-}"
    case "$cmd" in
      true|on|enable|1)
        need_root
        install -d -m 0755 "${stateDir}"
        : > "$FLAG"
        systemctl start "$UNIT"
        echo "OK: enabled (no suspend)"
        ;;
      false|off|disable|0)
        need_root
        rm -f "$FLAG"
        systemctl stop "$UNIT" 2>/dev/null || true
        echo "OK: disabled (suspend allowed)"
        ;;
      status)
        echo "Flag: $([ -f "$FLAG" ] && echo enabled || echo disabled)"
        echo "Service: $(systemctl is-active "$UNIT" 2>/dev/null || echo inactive)"
        echo
        echo "Inhibitors (filtered):"
        ${pkgs.systemd}/bin/systemd-inhibit --list | sed -n '1p;/dosuspend/p' || true
        ;;
      ""|-h|--help)
        usage
        ;;
      *)
        usage
        exit 1
        ;;
    esac
  '';

  dosuspeng = pkgs.runCommand "dosuspeng" {} ''
    mkdir -p $out/bin
    ln -s ${dosuspend}/bin/dosuspend $out/bin/dosuspeng
  '';
in {
  environment.systemPackages = [dosuspend dosuspeng];

  systemd.tmpfiles.rules = [
    "d ${stateDir} 0755 root root -"
  ];

  systemd.services.no-suspend-inhibit = {
    description = "Block suspend/hibernate via systemd-inhibit (toggle with dosuspend)";
    wantedBy = ["multi-user.target"];
    before = [
      "sleep.target"
      "suspend.target"
      "hibernate.target"
      "hybrid-sleep.target"
      "suspend-then-hibernate.target"
    ];

    unitConfig.ConditionPathExists = flagFile;

    serviceConfig = {
      Type = "simple";
      ExecStart = ''
        ${pkgs.systemd}/bin/systemd-inhibit \
          --what=sleep:idle:handle-lid-switch \
          --mode=block \
          --why="dosuspend: user requested to block suspend" \
          ${pkgs.coreutils}/bin/sleep infinity
      '';
      Restart = "always";
      RestartSec = 1;
    };
  };
}
