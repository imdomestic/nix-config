{
  lib,
  usernames ? [],
  ...
}: let
  resolvedUsernames = usernames;
  hasUser = needle: lib.any (u: lib.hasInfix needle u) resolvedUsernames;
in {
  services.aerospace =
    if hasUser "hank"
    then {
      enable = true;
      settings = {
        enable-normalization-flatten-containers = true;
        enable-normalization-opposite-orientation-for-nested-containers = true;
        default-root-container-layout = "accordion";
        default-root-container-orientation = "auto";
        on-window-detected = [
          {
            "if".app-id = "com.mitchellh.ghostty";
            run = [
              "layout floating"
            ];
          }
        ];

        mode = {
          main = {
            binding = {
              "alt-enter" = "exec-and-forget kitty";
              "alt-j" = "focus down";
              "alt-k" = "focus up";
              "alt-l" = "focus right";
              "alt-h" = "focus left";

              "alt-shift-h" = "move left";
              "alt-shift-j" = "move down";
              "alt-shift-k" = "move up";
              "alt-shift-l" = "move right";

              # 以下两行在 TOML 中被注释掉
              # "alt-h"    = "split horizontal";
              # "alt-v"    = "split vertical";

              "alt-f" = "fullscreen";

              "alt-s" = "layout v_accordion"; # 对应 i3 的 'layout stacking'
              "alt-w" = "layout h_accordion"; # 对应 i3 的 'layout tabbed'
              "alt-e" = "layout tiles horizontal vertical"; # 对应 i3 的 'layout toggle split'

              "alt-shift-space" = "layout floating tiling"; # 对应 i3 的 'floating toggle'

              # 以下两行在 TOML 中被注释掉，因为此命令在 AeroSpace 模型下冗余
              # "alt-space" = "focus toggle_tiling_floating";
              # "alt-a"     = "focus parent";

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
          };
        };

        # 窗口间隙配置
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
    }
    else if hasUser "linwhite"
    then {
    }
    else {};
}
