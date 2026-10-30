# hank 的 AeroSpace,由 users.hank.gui.darwin 加载(../user.nix),所以 hank 的
# 每台 Mac 桌面都有。Home Manager 管:配置写进 ~/.config/aerospace,launchd
# agent 跟着账户走,两个人的键位各用各的。
{config, ...}: let
  rex = "${config.home.homeDirectory}/.local/bin/rex";
in {
  programs.aerospace = {
    enable = true;
    launchd.enable = true;

    settings = {
      # nix-darwin 的 services.aerospace 原来会替我们写进这几项默认值。搬到
      # Home Manager 后照写,生成的 aerospace.toml 和原来逐字一致;其中
      # on-focused-monitor-changed 和 AeroSpace 自己的默认(空)不同。
      "accordion-padding" = 30;
      "after-startup-command" = [];
      "exec-on-workspace-change" = [];
      "on-focus-changed" = [];
      "on-focused-monitor-changed" = ["move-mouse monitor-lazy-center"];
      key-mapping.preset = "qwerty";
      workspace-to-monitor-force-assignment = {};

      enable-normalization-flatten-containers = true;
      enable-normalization-opposite-orientation-for-nested-containers = true;
      default-root-container-layout = "tiles";
      default-root-container-orientation = "auto";

      on-window-detected =
        # 整个应用都浮动:尺寸或宽高比固定,或者会弹出一堆小窗口。
        map (id: {
          "if".app-id = id;
          run = ["layout floating"];
        }) [
          "com.mitchellh.ghostty"
          "com.apple.Passwords"
          "com.apple.ScreenContinuity" # iPhone Mirroring
          "com.apple.systempreferences"
          "com.apple.calculator"
          "com.moonlight-stream.Moonlight"
          "com.apple.ScreenSharing"
          "com.apple.QuickTimePlayerX"
          "com.apple.FaceTime"
          "com.tencent.meeting" # 腾讯会议
          "com.tencent.tencentmeeting" # VooV Meeting
          "org.localsend.localsendApp"
          "com.macpaw.site.theunarchiver"
          "com.valvesoftware.steam"
        ]
        ++ [
          {
            # 微信只浮动图片/视频查看器,主窗口照常平铺。标题按界面语言是
            # 英文/简体/繁体三种(WeChat 4.1 的字符串表)。
            "if" = {
              app-id = "com.tencent.xinWeChat";
              window-title-regex-substring = "^(Photos and Videos|图片和视频|圖片和影片)$";
            };
            run = ["layout floating"];
          }
          {
            # Minecraft 的 Java 进程可能没有 bundle ID,用应用名和游戏标题匹配。
            "if" = {
              app-name-regex-substring = "^(java|Minecraft)$";
              window-title-regex-substring = "^Minecraft(\\s|$)";
            };
            run = ["layout floating"];
          }
        ];

      mode.main.binding = {
        # 新窗口带一个新 session。要 Rex 设置里 Rex Server 下的 Remote Control;
        # 没开或者 Rex 没在跑时 CLI 失败,open 只负责把 Rex 拉起来/提到前台。
        "alt-enter" = "exec-and-forget '${rex}' --autostart=false do client.window.new >/dev/null 2>&1; open -b com.superlogical.rex";

        "alt-h" = "focus left";
        "alt-j" = "focus down";
        "alt-k" = "focus up";
        "alt-l" = "focus right";

        "alt-shift-h" = "move left";
        "alt-shift-j" = "move down";
        "alt-shift-k" = "move up";
        "alt-shift-l" = "move right";

        # i3 的 split horizontal / vertical 没有搬过来:alt-h 已经是 focus left。
        "alt-f" = "fullscreen";

        "alt-s" = "layout v_accordion"; # 对应 i3 的 'layout stacking'
        "alt-w" = "layout h_accordion"; # 对应 i3 的 'layout tabbed'
        "alt-e" = "layout tiles horizontal vertical"; # 对应 i3 的 'layout toggle split'

        # 三态轮换:水平平铺 → 垂直平铺 → 水平手风琴 → 回到水平平铺。
        # `layout` 不是循环,而是「从左往右取第一个不描述当前布局的参数」
        # (man aerospace-layout),所以这个顺序是推出来的、调不得:前两态
        # 都被 tiles 匹配掉,轮到手风琴态时 tiles 不匹配,于是换回平铺并保留
        # 水平朝向,刚好闭环。手风琴那一档必须写死 h_accordion —— 写成裸
        # accordion 的话回程会停在垂直平铺,三态退化成两态来回。
        "alt-r" = "layout tiles v_tiles h_accordion";

        "alt-shift-space" = "layout floating tiling"; # 对应 i3 的 'floating toggle'

        # i3 的 focus toggle_tiling_floating / focus parent 也没搬:
        # AeroSpace 的模型里这两条是冗余的。

        "alt-1" = "workspace 1";
        "alt-2" = "workspace 2";
        "alt-3" = "workspace 3";
        "alt-4" = "workspace 4";
        "alt-5" = "workspace 5";
        "alt-6" = "workspace 6";
        "alt-7" = "workspace 7";
        "alt-8" = "workspace 8";
        "alt-9" = "workspace 9";
        "alt-0" = "workspace 10";

        "alt-shift-1" = "move-node-to-workspace 1";
        "alt-shift-2" = "move-node-to-workspace 2";
        "alt-shift-3" = "move-node-to-workspace 3";
        "alt-shift-4" = "move-node-to-workspace 4";
        "alt-shift-5" = "move-node-to-workspace 5";
        "alt-shift-6" = "move-node-to-workspace 6";
        "alt-shift-7" = "move-node-to-workspace 7";
        "alt-shift-8" = "move-node-to-workspace 8";
        "alt-shift-9" = "move-node-to-workspace 9";
        "alt-shift-0" = "move-node-to-workspace 10";

        "alt-shift-c" = "reload-config";

        "alt-left" = "resize width -50";
        "alt-right" = "resize width +50";
        "alt-up" = "resize height +50";
        "alt-down" = "resize height -50";
      };

      gaps = {
        inner = {
          horizontal = 8;
          vertical = 8;
        };
        outer = {
          left = 8;
          bottom = 8;
          top = 8;
          right = 8;
        };
      };
    };
  };
}
