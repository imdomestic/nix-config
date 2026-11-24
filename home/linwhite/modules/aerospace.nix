# linwhite 的 macOS 窗口管理；aegis 的显示器和 Rex 规则在 ../aegis.nix。
{lib, ...}: let
  digits = ["1" "2" "3" "4" "5" "6" "7" "8" "9" "0"];
  digitBindings = prefix: command:
    lib.listToAttrs (map (digit: {
        name = "${prefix}${digit}";
        value = "${command} ${digit}";
      })
      digits);
in {
  programs.aerospace = {
    enable = true;
    launchd.enable = true;

    settings = {
      "default-root-container-layout" = "tiles";
      "default-root-container-orientation" = "auto";
      "on-focused-monitor-changed" = ["move-mouse monitor-lazy-center"];
      # Rex 在 aegis 上依赖 macOS 的隐藏功能。
      "automatically-unhide-macos-hidden-apps" = false;
      "key-mapping".preset = "qwerty";

      gaps = {
        inner = {
          horizontal = 0;
          vertical = 0;
        };
        outer = {
          left = 0;
          bottom = 0;
          top = 0;
          right = 0;
        };
      };

      "on-window-detected" = [
        # LTspice 使用多个独立的编辑、绘图和对话窗口。
        {
          "if".app-id = "com.analog.LTspice.App";
          run = "layout floating";
        }
        {
          "if".app-id = "com.analog.ltspice";
          run = "layout floating";
        }
        # 首条匹配即停止：微信主窗口平铺，其余窗口浮动。
        {
          "if" = {
            app-id = "com.tencent.xinWeChat";
            window-title-regex-substring = "^(WeChat|微信)( \\((Chats|聊天)\\))?$";
          };
          run = "layout tiling";
        }
        {
          "if".app-id = "com.tencent.xinWeChat";
          run = "layout floating";
        }
        # MATLAB 主窗口平铺，对话框浮动。
        {
          "if" = {
            app-id = "com.mathworks.matlab";
            window-title-regex-substring = "(?i)^MATLAB R[0-9]{4}[ab].*";
          };
          run = "layout tiling";
        }
        {
          "if".app-id = "com.mathworks.matlab";
          run = "layout floating";
        }
        {
          "if" = {
            app-name-regex-substring = "(?i)gnuplot(_qt)?";
            window-title-regex-substring = "(?i)(^$|preferences|settings|about|open|save|print|select|choose|warning|error|confirm|question|dialog|property|properties|设置|首选项|保存|打开|警告|错误|确认)";
          };
          run = "layout floating";
        }
      ];

      mode.main.binding =
        {
          "alt-slash" = "layout tiles horizontal vertical";
          "alt-comma" = "layout accordion horizontal vertical";
          "alt-shift-space" = "layout floating tiling";

          "alt-h" = "focus left";
          "alt-j" = "focus down";
          "alt-k" = "focus up";
          "alt-l" = "focus right";
          "alt-ctrl-h" = "focus-monitor left";
          "alt-ctrl-l" = "focus-monitor right";

          "alt-shift-h" = "move left";
          "alt-shift-j" = "move down";
          "alt-shift-k" = "move up";
          "alt-shift-l" = "move right";
          "alt-shift-minus" = "resize smart -50";
          "alt-shift-equal" = "resize smart +50";

          "alt-tab" = "workspace-back-and-forth";
          "alt-shift-semicolon" = "mode service";
        }
        // digitBindings "alt-" "summon-workspace"
        // digitBindings "alt-shift-" "move-node-to-workspace";

      mode.service.binding = {
        "esc" = ["reload-config" "mode main"];
        "r" = ["flatten-workspace-tree" "mode main"];
        "f" = ["layout floating tiling" "mode main"];
        "backspace" = ["close-all-windows-but-current" "mode main"];
        "alt-shift-h" = ["join-with left" "mode main"];
        "alt-shift-j" = ["join-with down" "mode main"];
        "alt-shift-k" = ["join-with up" "mode main"];
        "alt-shift-l" = ["join-with right" "mode main"];
        "down" = "volume down";
        "up" = "volume up";
        "shift-down" = ["volume set 0" "mode main"];
      };
    };
  };
}
