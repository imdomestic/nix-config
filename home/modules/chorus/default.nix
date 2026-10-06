{
  config,
  lib,
  pkgs,
  ...
}:
# 只在 encore（MC 开发机）上装这两个脚本，不落到 Mac / 9950x 的 home。
lib.mkIf (config.my.host.name == "encore") {
  home.packages = [
    (pkgs.writeShellScriptBin "mc-client" ''
      #!/usr/bin/env bash
      # mc-client —— 在 encore 上（从 SSH / tmux 里）启动 Fabric 开发客户端。
      # 窗口会开在 encore 已登录的桌面会话上，你在 Mac 上用 Moonlight 看和操作。
      #
      #   mc-client            正常启动
      #   mc-client --debug    启动后停在 5005 端口等调试器；在 nvim 里 <leader>dc 选
      #                        "Attach: encore 本机客户端" 后游戏才继续加载
      #
      # 环境变量：
      #   MC_DGPU=0            不用独显（默认走 NVIDIA PRIME offload）
      set -euo pipefail

      root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
        echo "mc-client: 请在 chorus 仓库里运行" >&2
        exit 1
      }
      cd "$root"

      # 1) SSH 会话里没有 DISPLAY / WAYLAND_DISPLAY，从 systemd 用户会话里借过来
      #    （桌面环境启动时会把这些变量导入 systemd --user）
      while IFS= read -r line; do
        case "$line" in
          DISPLAY=* | WAYLAND_DISPLAY=* | XAUTHORITY=* | XDG_SESSION_TYPE=*) export "''${line?}" ;;
        esac
      done < <(systemctl --user show-environment 2>/dev/null || true)
      export XDG_RUNTIME_DIR="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

      if [[ -z "''${DISPLAY:-}''${WAYLAND_DISPLAY:-}" ]]; then
        echo "mc-client: encore 上没有找到已登录的图形会话（检查 autoLogin，或先在本机登录一次）" >&2
        exit 1
      fi

      # 2) 笔记本混合显卡：让 MC 跑在 RTX 上而不是核显
      if [[ "''${MC_DGPU:-1}" == 1 ]]; then
        export __NV_PRIME_RENDER_OFFLOAD=1
        export __NV_PRIME_RENDER_OFFLOAD_PROVIDER=NVIDIA-G0
        export __GLX_VENDOR_LIBRARY_NAME=nvidia
        export __VK_LAYER_NV_optimus=NVIDIA_only
      fi

      # 3) 确保 devenv 已加载（JDK 25 + NixOS 运行库）。
      #    在 direnv 已生效的 shell 里直接跑；否则临时进一次 dev shell。
      args=(:fabric:runClient)
      if [[ "''${1:-}" == "--debug" ]]; then
        args+=(--debug-jvm)
        echo "mc-client: 等待调试器连接 127.0.0.1:5005 ……"
      fi

      if [[ -n "''${DEVENV_STATE:-}" ]]; then
        exec ./gradlew "''${args[@]}"
      else
        exec nix develop --no-pure-eval --command ./gradlew "''${args[@]}"
      fi
    '')
    (pkgs.writeShellScriptBin "mc-server-remote" ''
      #!/usr/bin/env bash
      # mc-server-remote —— 在 encore 上运行：把当前工作区同步到 9950X，在那边跑 Fabric 开发服务端。
      # 用来测“真·客户端/服务端分离”：客户端在 encore，服务端在另一台机器，走 tailscale。
      #
      #   mc-server-remote           同步代码 →（停掉旧服务端）→ 启动 → 跟随日志（Ctrl-C 只退出日志，服务端继续跑）
      #   mc-server-remote --debug   服务端停在 5005 等调试器；同时建好 encore:5006 → 9950X:5005 的隧道，
      #                              在 nvim 里 <leader>dc 选 “Attach: 9950X 服务端”
      #   mc-server-remote stop      停掉远端服务端
      #
      # 客户端（mc-client）里：多人游戏 → 添加服务器 → <MC_SERVER_HOST>:25565
      set -euo pipefail

      HOST="''${MC_SERVER_HOST:-9950x}"
      REMOTE_DIR="''${MC_SERVER_DIR:-chorus}" # 远端 $HOME 下的目录
      SESSION="chorus-server"
      LOG=".cache/chorus-server.log" # 远端 $HOME 下；放在仓库外，免得被 rsync --delete 删掉

      stop_remote() {
        # 先发 stop 让服务端正常存档退出，20 秒还没退就强制结束
        ssh "$HOST" "
          if tmux has-session -t $SESSION 2>/dev/null; then
            tmux send-keys -t $SESSION stop Enter
            for i in \$(seq 20); do tmux has-session -t $SESSION 2>/dev/null || break; sleep 1; done
            tmux kill-session -t $SESSION 2>/dev/null || true
          fi"
      }

      if [[ "''${1:-}" == "stop" ]]; then
        stop_remote
        echo "已停止 $HOST 上的服务端"
        exit 0
      fi

      root="$(git rev-parse --show-toplevel 2>/dev/null)" || {
        echo "mc-server-remote: 请在 chorus 仓库里运行" >&2
        exit 1
      }
      cd "$root"

      echo "→ 同步代码到 $HOST:~/$REMOTE_DIR"
      rsync -az --delete \
        --exclude '.gradle/' --exclude 'build/' --exclude 'bin/' --exclude 'runs/' \
        --exclude '.direnv/' --exclude '.devenv*' \
        ./ "$HOST:$REMOTE_DIR/"

      debug_flag=""
      if [[ "''${1:-}" == "--debug" ]]; then
        debug_flag="--debug-jvm"
        if ssh -fN -o ExitOnForwardFailure=yes -L 5006:127.0.0.1:5005 "$HOST" 2>/dev/null; then
          echo "→ 调试隧道 encore:5006 → $HOST:5005 已建立"
        else
          echo "→ 5006 端口已被占用（多半是上次的隧道还在），直接沿用"
        fi
      fi

      echo "→ 重启远端服务端"
      stop_remote

      # 首次运行：同意 EULA；关掉正版验证（开发客户端用的是离线账号，不关进不去服）
      ssh "$HOST" bash -s -- "$REMOTE_DIR" <<'EOF'
      set -e
      run="$HOME/$1/fabric/runs/server"
      props="$run/server.properties"
      mkdir -p "$run" "$HOME/.cache"
      echo "eula=true" > "$run/eula.txt"
      if [ -f "$props" ] && grep -q '^online-mode=' "$props"; then
        sed -i 's/^online-mode=.*/online-mode=false/' "$props"
      else
        echo "online-mode=false" >> "$props"
      fi
      EOF

      # 远端用不挂载的 tmux 会话跑（避免和 encore 上的 tmux 嵌套），输出同时写进日志文件
      ssh "$HOST" "tmux new-session -d -s $SESSION \
        'cd ~/$REMOTE_DIR && nix develop --no-pure-eval --command ./gradlew :fabric:runServer $debug_flag 2>&1 | tee ~/$LOG'"

      echo "→ 服务端已在 $HOST 启动（tmux 会话 $SESSION），下面是日志；Ctrl-C 只退出日志"
      [[ -n "$debug_flag" ]] && echo "   服务端在等调试器：nvim 里 <leader>dc → Attach: 9950X 服务端"
      sleep 1
      exec ssh "$HOST" "tail -n 50 -F ~/$LOG"
    '')
  ];
}
