# 正在进行的 nix 构建,导出成 node_exporter 的 textfile 指标。
#
# 起因:tank 当上构建机之后,"这台机器现在在替谁编什么"变成一个常问的问题,
# 而 nix 本身不导出任何指标。
#
# ---------------------------------------------------------------------------
# 能测什么,不能测什么 —— 先说清楚,免得看板给人错觉:
#
#   **正在跑的:能。** builder 进程的 environ 里有 `name` / `pname` /
#   `version` / `out`,这是唯一可靠的来源 —— 沙箱开着的时候构建目录在私有
#   mount namespace 里,/tmp 和 TMPDIR 下都看不到(实测 tank 的
#   /data/builds 里只有 sccache)。
#
#   **排队的:不能。** nix 的构建队列是**客户端进程内存里**的 Worker 对象,
#   没有文件、没有 socket API、没有任何导出。等 slot 的 goal 只存在于那个
#   跑着 nixos-rebuild 的进程里。这里不假装能测它。
#
#   唯一的近似是 nix_daemon_remote_sessions:远程会话数和本机 max-jobs 的
#   差值约等于"在这台上排队的远程构建",但它覆盖不到本地队列。
# ---------------------------------------------------------------------------
{
  config,
  lib,
  pkgs,
  inputs,
  ...
}: let
  cfg = config.my.telemetry;

  inventory =
    (import ../../../lib/mkInventory.nix {inherit inputs;})
    {hosts = import ../../hosts {inherit inputs;};};

  # tailnet IP → 主机名,用来把远程构建会话标成人能看懂的来源。
  ipToName = lib.concatMapStrings (h: "${h.tsIp} ${h.name}\n") inventory;

  script = pkgs.writeShellApplication {
    name = "nix-build-metrics";
    runtimeInputs = [pkgs.procps pkgs.coreutils];
    text = ''
      dir=${lib.escapeShellArg cfg.textfileDir}
      out="$dir/nix_builds.prom"
      tmp="$(mktemp "$dir/.nix_builds.XXXXXX")"
      trap 'rm -f "$tmp"' EXIT

      # --- 找出 nix-daemon 的全部后代 ---
      #
      # **不扫全部 /proc。** 无差别读 environ 会读到 cliproxy、ddns-go、max
      # 这些服务的环境变量,里面是 API key 和管理口令 —— 这个脚本以 root 跑,
      # 读得到,而输出文件是给 node_exporter 读的 0644。把范围限死在
      # nix-daemon 的进程树里,既便宜也不碰无关服务。
      declare -A ppid_of=()
      declare -a all_pids=()
      while read -r pid ppid; do
        ppid_of[$pid]=$ppid
        all_pids+=("$pid")
      done < <(ps -eo pid=,ppid= 2>/dev/null)

      declare -A is_daemon=()
      while read -r pid; do
        [ -n "$pid" ] && is_daemon[$pid]=1
      done < <(pgrep -x nix-daemon 2>/dev/null || true)

      # 逐个进程向上回溯到 init,路上撞到 nix-daemon 就算数。
      declare -a build_pids=()
      for pid in "''${all_pids[@]}"; do
        p=$pid
        hops=0
        while [ -n "''${p:-}" ] && [ "$p" != "1" ] && [ "$hops" -lt 32 ]; do
          if [ -n "''${is_daemon[$p]:-}" ]; then
            build_pids+=("$pid")
            break
          fi
          p="''${ppid_of[$p]:-}"
          hops=$((hops + 1))
        done
      done

      # --- 从 environ 里取 derivation 信息 ---
      #
      # 用 out=(输出路径)去重:一个 derivation 会派生一大串进程(bash、
      # qemu、编译器),它们共享同一份 environ,不去重会把一个构建数成几十个。
      declare -A seen=()
      declare -a lines=()
      for pid in "''${build_pids[@]}"; do
        [ -r "/proc/$pid/environ" ] || continue
        env_txt="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null || true)"

        outp=""; pname=""; version=""
        while IFS= read -r kv; do
          case "$kv" in
            out=*)     outp="''${kv#out=}" ;;
            pname=*)   pname="''${kv#pname=}" ;;
            version=*) version="''${kv#version=}" ;;
          esac
        done <<< "$env_txt"

        # 没有 out= 的不是 builder(daemon 自己、ssh 包装进程等)。
        [ -n "$outp" ] || continue
        [ -n "''${seen[$outp]:-}" ] && continue
        seen[$outp]=1

        # pname 缺失时退回从 out 路径里截名字。
        if [ -z "$pname" ]; then
          pname="''${outp##*/}"
          pname="''${pname#*-}"
        fi
        # 标签值里的反斜杠和引号要转义,否则一个古怪的包名能让整个文件作废。
        pname="''${pname//\\/\\\\}"; pname="''${pname//\"/\\\"}"
        version="''${version//\\/\\\\}"; version="''${version//\"/\\\"}"

        lines+=("nix_build_running{pname=\"$pname\",version=\"$version\"} 1")
      done

      # --- 远程构建会话:谁在用这台机器编东西 ---
      #
      # tailscale SSH 的包装进程带 --remote-ip=<tailnet 地址>,而每个远程
      # 构建都是一路 `nix-daemon --stdio`。数 IP 就知道是替谁在干活。
      declare -A ip_name=()
      while read -r ip name; do
        [ -n "$ip" ] && ip_name[$ip]=$name
      done <<< ${lib.escapeShellArg ipToName}

      # 匹配全部用 bash 内置的 case,不调 grep —— grep 不在 runtimeInputs 里,
      # 而 writeShellApplication 会把 PATH 限死;调它会是运行时才暴露的
      # "command not found",shellcheck 也查不出来(见 modules/telemetry/mesh.nix
      # 里 awk 那次的注释)。
      declare -A sessions=()
      while read -r args; do
        case "$args" in
          *"--cmd=nix-daemon --stdio"*)
            case "$args" in
              *--remote-ip=*)
                rest="''${args#*--remote-ip=}"
                ip="''${rest%% *}"
                key="''${ip_name[$ip]:-$ip}"
                sessions[$key]=$(( ''${sessions[$key]:-0} + 1 ))
                ;;
            esac
            ;;
        esac
      done < <(ps -eo args= 2>/dev/null || true)

      {
        echo "# HELP nix_build_running A derivation currently being built on this machine."
        echo "# TYPE nix_build_running gauge"
        if [ ''${#lines[@]} -gt 0 ]; then printf '%s\n' "''${lines[@]}"; fi

        echo "# HELP nix_builds_running Number of distinct derivations currently building."
        echo "# TYPE nix_builds_running gauge"
        echo "nix_builds_running ''${#seen[@]}"

        echo "# HELP nix_daemon_remote_sessions Remote nix-daemon --stdio sessions, by originating tailnet peer."
        echo "# TYPE nix_daemon_remote_sessions gauge"
        for k in "''${!sessions[@]}"; do
          echo "nix_daemon_remote_sessions{peer=\"$k\"} ''${sessions[$k]}"
        done
      } > "$tmp"

      chmod 0644 "$tmp"
      mv "$tmp" "$out"
    '';
  };
in {
  config = lib.mkIf cfg.mesh {
    systemd.services.nix-build-metrics = {
      description = "把正在进行的 nix 构建写成 node_exporter textfile 指标";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe script;
        # 需要 root:builder 跑在 nixbld* 用户下,/proc/<pid>/environ 只有
        # 属主和 root 读得到。
        User = "root";
        ReadWritePaths = [cfg.textfileDir];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        # ProtectProc 必须留默认(不隔离)—— 整个脚本就是靠读别的进程的
        # /proc 工作的。
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };

    systemd.timers.nix-build-metrics = {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = "1m";
        OnUnitActiveSec = "30s";
        AccuracySec = "5s";
      };
    };
  };
}
