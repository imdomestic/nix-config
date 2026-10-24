# linwhite 在 aegis 上的东西。
#
# 这台接的 EK1080T2KHR 是 HDMI 诱骗器:只为 KVM 切走时机器不锁屏、切回来不重排。
# AeroSpace 没有"忽略某个显示器"的选项,所以分两步:所有命名工作区强制钉在别的显示器上,
# 守卫脚本再把漏到诱骗器上的窗口和焦点挪走。只剩诱骗器时(KVM 切走)什么都不做。
{
  pkgs,
  config,
  lib,
  ...
}: let
  dummy = "EK1080T2KHR";
  aerospace = "${config.programs.aerospace.package}/bin/aerospace";

  evict = pkgs.writeShellScript "aerospace-evict-dummy" ''
    target=$(${aerospace} list-monitors --format '%{monitor-id}|%{monitor-name}' |
      grep -v '|${dummy}$' | head -n1 | cut -d'|' -f1)
    [ -n "$target" ] || exit 0

    ${aerospace} list-windows --monitor all --format '%{window-id}|%{monitor-name}' |
      while IFS='|' read -r wid mon; do
        [ "$mon" = '${dummy}' ] || continue
        ${aerospace} move-node-to-monitor --window-id "$wid" "$target"
      done

    if [ "$(${aerospace} list-monitors --focused --format '%{monitor-name}')" = '${dummy}' ]; then
      ${aerospace} focus-monitor "$target"
    fi
  '';
in {
  programs.aerospace.settings = {
    # 显示器 pattern 是正则;没有其他显示器匹配时 AeroSpace 自己回落到现有显示器。
    "workspace-to-monitor-force-assignment" = builtins.listToAttrs (map (ws: {
      name = ws;
      value = "^(?!${dummy}$).*$";
    }) ["1" "2" "3" "4" "5" "6" "7" "8" "9" "0"]);

    # 排在 linwhite 自己的命令之后(先 move-mouse 再挪窗口),和原来一致。
    "after-startup-command" = lib.mkAfter ["exec-and-forget ${evict}"];
    "on-focused-monitor-changed" = lib.mkAfter ["exec-and-forget ${evict}"];
    "exec-on-workspace-change" = lib.mkAfter ["${evict}"];
  };

  programs.claude-code.settings = {
    env = {
      # macOS 上仅使用 system 时，当前运行时读取的 CA 无法验证 Anthropic 证书。
      CLAUDE_CODE_CERT_STORE = "bundled,system";
      CLAUDE_CODE_SUBAGENT_MODEL = "haiku";
      CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS = "8";
    };
    model = "opus";
    statusLine = {
      type = "command";
      command = "sh ${config.home.homeDirectory}/.claude/statusline-command.sh";
    };
    modelSettings.claude-opus-5-5.effortLevel = "xhigh";
    skipDangerousModePermissionPrompt = true;
    enabledPlugins."swift-lsp@claude-plugins-official" = true;
  };
}
