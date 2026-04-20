{
  enable = true;

  settings = {
    # "config-version" = 2;
    "after-startup-command" = [];
    "enable-normalization-flatten-containers" = true;
    "enable-normalization-opposite-orientation-for-nested-containers" = true;
    "accordion-padding" = 30;
    "default-root-container-layout" = "tiles";
    "default-root-container-orientation" = "auto";
    "on-focused-monitor-changed" = ["move-mouse monitor-lazy-center"];
    "automatically-unhide-macos-hidden-apps" = false;
    "on-window-detected" = [
      # Keep WeChat main window tiled; float all other WeChat windows (popups, dialogs).
      {
        "if" = {
          app-id = "com.tencent.xinWeChat";
          window-title-regex-substring = "^(WeChat|微信)( \\((Chats|聊天)\\))?$";
        };
        run = "layout tiling";
      }
      {
        "if" = {
          app-id = "com.tencent.xinWeChat";
          # Float any WeChat window that is NOT the main chat window.
          window-title-regex-substring = "^(?!((WeChat|微信)( \\((Chats|聊天)\\))?$)).*";
        };
        run = "layout floating";
      }
      # Float common MATLAB dialog windows while keeping main editor/command windows tiled.
      {
        "if" = {
          app-id = "com.mathworks.matlab";
          window-title-regex-substring = "(?i)^MATLAB R[0-9]{4}[ab].*";
        };
        run = "layout tiling";
      }
      {
        "if" = {
          app-id = "com.mathworks.matlab";
        };
        run = "layout floating";
      }
      # gnuplot helper windows are usually popup-style; float them by app name + title keywords.
      {
        "if" = {
          app-name-regex-substring = "(?i)gnuplot(_qt)?";
          window-title-regex-substring = "(?i)(^$|preferences|settings|about|open|save|print|select|choose|warning|error|confirm|question|dialog|property|properties|设置|首选项|保存|打开|警告|错误|确认)";
        };
        run = "layout floating";
      }
    ];
    # "persistent-workspaces" = [ "1" "2" "3" "4" "5" "6" "7" "8" "9" "0" ];
    # "on-mode-changed" = [ ];

    "key-mapping" = {
      preset = "qwerty";
    };

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

    mode = {
      main = {
        binding = {
          "alt-slash" = "layout tiles horizontal vertical";
          "alt-comma" = "layout accordion horizontal vertical";

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

          # In multi-monitor setups, summon-workspace brings target workspace
          # to the currently focused monitor instead of jumping to its assigned one.
          "alt-1" = "summon-workspace 1";
          "alt-2" = "summon-workspace 2";
          "alt-3" = "summon-workspace 3";
          "alt-4" = "summon-workspace 4";
          "alt-5" = "summon-workspace 5";
          "alt-6" = "summon-workspace 6";
          "alt-7" = "summon-workspace 7";
          "alt-8" = "summon-workspace 8";
          "alt-9" = "summon-workspace 9";
          "alt-0" = "summon-workspace 0";

          "alt-shift-1" = "move-node-to-workspace 1";
          "alt-shift-2" = "move-node-to-workspace 2";
          "alt-shift-3" = "move-node-to-workspace 3";
          "alt-shift-4" = "move-node-to-workspace 4";
          "alt-shift-5" = "move-node-to-workspace 5";
          "alt-shift-6" = "move-node-to-workspace 6";
          "alt-shift-7" = "move-node-to-workspace 7";
          "alt-shift-8" = "move-node-to-workspace 8";
          "alt-shift-9" = "move-node-to-workspace 9";
          "alt-shift-0" = "move-node-to-workspace 0";

          "alt-tab" = "workspace-back-and-forth";
          # "alt-shift-tab" = "move-node-to-workspace-back-and-forth";

          "alt-shift-semicolon" = "mode service";
        };
      };

      service = {
        binding = {
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
  };
}
