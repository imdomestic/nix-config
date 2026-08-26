# hank 的 AeroSpace。按用户分文件、由 host 显式 import(m1elite / hackintosh),
# 不在模块里按 config.my.host.usernames 猜:aerospace 的配置是整机一份
# (/etc/aerospace.toml),两个人的键位互不兼容,谁的机器谁自己写死。
# linwhite 的那份在 ./linwhite.nix。
_: {
  services.aerospace = {
    enable = true;

    settings = {
      enable-normalization-flatten-containers = true;
      enable-normalization-opposite-orientation-for-nested-containers = true;
      default-root-container-layout = "tiles";
      default-root-container-orientation = "auto";

      on-window-detected = [
        {
          "if".app-id = "com.mitchellh.ghostty";
          run = ["layout floating"];
        }
      ];

      mode.main.binding = {
        "alt-enter" = "exec-and-forget kitty";

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
          horizontal = 10;
          vertical = 10;
        };
        outer = {
          left = 10;
          bottom = 10;
          top = 10;
          right = 10;
        };
      };
    };
  };
}
