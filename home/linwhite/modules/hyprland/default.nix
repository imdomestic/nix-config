{
  lib,
  pkgs,
  ...
}: let
  clamshell = pkgs.writeShellScript "hyprland-clamshell" ''
    if grep -q "closed" /proc/acpi/button/lid/*/state 2>/dev/null; then
      if ${pkgs.hyprland}/bin/hyprctl monitors all | grep -v "eDP-1" | grep -q "Monitor "; then
        ${pkgs.hyprland}/bin/hyprctl keyword monitor "eDP-1, disable"
      fi
    else
      ${pkgs.hyprland}/bin/hyprctl keyword monitor "eDP-1, preferred, auto, 1"
    fi
  '';
in {
  wayland.windowManager.hyprland = {
    enable = true;
    xwayland.enable = true;
    configType = "hyprlang";
    settings = {
      "$mod" = "SUPER";

      monitor = [
        ",preferred,auto,1"
      ];

      env = [
        # 混合显卡：笔记本内屏由 Intel 核显（card1）直连驱动，HDMI / 独显加速走 NVIDIA（card0）
        "AQ_DRM_DEVICES,/dev/dri/card1:/dev/dri/card0"
        "NIXOS_OZONE_WL,1"
        "ELECTRON_OZONE_PLATFORM_HINT,auto"
        "QT_QPA_PLATFORM,wayland;xcb"
        "QT_WAYLAND_DISABLE_WINDOWDECORATION,1"
        "GDK_BACKEND,wayland,x11,*"
        "SDL_VIDEODRIVER,wayland"
        "CLUTTER_BACKEND,wayland"
        "XDG_CURRENT_DESKTOP,Hyprland"
        "XDG_SESSION_TYPE,wayland"
        "XDG_SESSION_DESKTOP,Hyprland"
        "XCURSOR_SIZE,24"
        "QT_IM_MODULE,fcitx"
        "GTK_IM_MODULE,fcitx"
        "XMODIFIERS,@im=fcitx"
      ];

      exec = [
        "${clamshell}"
      ];

      exec-once = [
        "dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP"
        "systemctl --user import-environment WAYLAND_DISPLAY XDG_CURRENT_DESKTOP"
        "/run/current-system/sw/bin/fcitx5 -d --replace"
        "${pkgs.waybar}/bin/waybar"
        "${pkgs.mako}/bin/mako"
        "${pkgs.polkit_gnome}/libexec/polkit-gnome-authentication-agent-1"
      ];

      general = {
        gaps_in = 4;
        gaps_out = 8;
        border_size = 2;
        "col.active_border" = "rgba(7aa2f7ee) rgba(bb9af7ee) 45deg";
        "col.inactive_border" = "rgba(414868aa)";
        layout = "dwindle";
      };

      decoration = {
        rounding = 8;
        blur = {
          enabled = true;
          size = 4;
          passes = 2;
        };
        shadow = {
          enabled = true;
          range = 12;
          render_power = 3;
          color = "rgba(1a1b2688)";
        };
      };

      animations = {
        enabled = true;
        bezier = "easeOutQuint, 0.23, 1, 0.32, 1";
        animation = [
          "windows, 1, 4, easeOutQuint"
          "windowsOut, 1, 4, default, popin 80%"
          "border, 1, 6, default"
          "fade, 1, 4, default"
          "workspaces, 1, 4, default"
        ];
      };

      dwindle = {
        preserve_split = true;
      };

      input = {
        kb_layout = "us";
        follow_mouse = 1;
        touchpad = {
          natural_scroll = true;
          tap-to-click = true;
        };
        sensitivity = 0;
      };

      bind = [
        # Applications
        "$mod, Return, exec, ${lib.getExe pkgs.ghostty}"
        "$mod, Space, exec, vicinae toggle || ${lib.getExe pkgs.rofi} -show drun"
        "$mod, D, exec, ${lib.getExe pkgs.rofi} -show drun"
        "$mod, B, exec, ${lib.getExe pkgs.google-chrome}"

        # Window management
        "$mod, Q, killactive"
        "$mod, M, exit"
        "$mod, F, fullscreen, 0"
        "$mod SHIFT, Space, togglefloating"
        "$mod, P, pseudo"
        "$mod, S, layoutmsg, togglesplit"

        # Focus with vim keys
        "$mod, H, movefocus, l"
        "$mod, L, movefocus, r"
        "$mod, K, movefocus, u"
        "$mod, J, movefocus, d"

        # Move window with vim keys
        "$mod SHIFT, H, movewindow, l"
        "$mod SHIFT, L, movewindow, r"
        "$mod SHIFT, K, movewindow, u"
        "$mod SHIFT, J, movewindow, d"

        # Switch workspaces (summon to current focused monitor)
        "$mod, 1, focusworkspaceoncurrentmonitor, 1"
        "$mod, 2, focusworkspaceoncurrentmonitor, 2"
        "$mod, 3, focusworkspaceoncurrentmonitor, 3"
        "$mod, 4, focusworkspaceoncurrentmonitor, 4"
        "$mod, 5, focusworkspaceoncurrentmonitor, 5"
        "$mod, 6, focusworkspaceoncurrentmonitor, 6"
        "$mod, 7, focusworkspaceoncurrentmonitor, 7"
        "$mod, 8, focusworkspaceoncurrentmonitor, 8"
        "$mod, 9, focusworkspaceoncurrentmonitor, 9"
        "$mod, 0, focusworkspaceoncurrentmonitor, 10"

        # Move active window to workspace
        "$mod SHIFT, 1, movetoworkspace, 1"
        "$mod SHIFT, 2, movetoworkspace, 2"
        "$mod SHIFT, 3, movetoworkspace, 3"
        "$mod SHIFT, 4, movetoworkspace, 4"
        "$mod SHIFT, 5, movetoworkspace, 5"
        "$mod SHIFT, 6, movetoworkspace, 6"
        "$mod SHIFT, 7, movetoworkspace, 7"
        "$mod SHIFT, 8, movetoworkspace, 8"
        "$mod SHIFT, 9, movetoworkspace, 9"
        "$mod SHIFT, 0, movetoworkspace, 10"

        # Workspace switching
        "$mod, Tab, workspace, previous"

        # Screenshots
        "$mod SHIFT, S, exec, ${lib.getExe pkgs.grimblast} copy area"
        ", Print, exec, ${lib.getExe pkgs.grimblast} copy output"
      ];

      bindm = [
        "$mod, mouse:272, movewindow"
        "$mod, mouse:273, resizewindow"
      ];

      bindel = [
        ", XF86AudioRaiseVolume, exec, ${pkgs.wireplumber}/bin/wpctl set-volume -l 1.5 @DEFAULT_AUDIO_SINK@ 5%+"
        ", XF86AudioLowerVolume, exec, ${pkgs.wireplumber}/bin/wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"
        ", XF86AudioMute, exec, ${pkgs.wireplumber}/bin/wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"
        ", XF86AudioMicMute, exec, ${pkgs.wireplumber}/bin/wpctl set-mute @DEFAULT_AUDIO_SOURCE@ toggle"
        ", XF86MonBrightnessUp, exec, ${pkgs.brightnessctl}/bin/brightnessctl set 5%+"
        ", XF86MonBrightnessDown, exec, ${pkgs.brightnessctl}/bin/brightnessctl set 5%-"
      ];

      bindl = [
        ", switch:on:Lid Switch, exec, ${clamshell}"
        ", switch:off:Lid Switch, exec, ${clamshell}"
        ", XF86AudioNext, exec, ${lib.getExe pkgs.playerctl} next"
        ", XF86AudioPause, exec, ${lib.getExe pkgs.playerctl} play-pause"
        ", XF86AudioPlay, exec, ${lib.getExe pkgs.playerctl} play-pause"
        ", XF86AudioPrev, exec, ${lib.getExe pkgs.playerctl} previous"
      ];

      windowrule = [
        "match:class .*, suppress_event maximize"
        "match:class ^(pavucontrol)$, float on"
        "match:class ^(nm-connection-editor)$, float on"
        "match:class ^(blueman-manager)$, float on"
        "match:class ^(org.gnome.FileRoller)$, float on"
        "match:class ^(vicinae)$, float on"
        "match:class ^(com.tencent.xinWeChat)$, match:title ^(?!微信|WeChat).*, float on"
        "match:title ^(Open File|Save File|Choose Folder|Select File).*, float on"
      ];
    };
  };

  programs.waybar = {
    enable = true;
    systemd.enable = false;
    settings = {
      mainBar = {
        layer = "top";
        position = "top";
        height = 36;
        spacing = 6;
        modules-left = [
          "hyprland/workspaces"
          "hyprland/window"
        ];
        modules-center = [
          "clock"
        ];
        modules-right = [
          "pulseaudio"
          "backlight"
          "battery"
          "cpu"
          "memory"
          "tray"
        ];
        "hyprland/workspaces" = {
          format = "{name}";
          on-click = "activate";
          all-outputs = true;
        };
        "hyprland/window" = {
          max-length = 40;
          separate-outputs = true;
        };
        tray = {
          spacing = 10;
        };
        clock = {
          format = "{:%Y-%m-%d  %H:%M}";
          tooltip-format = "<tt><small>{calendar}</small></tt>";
        };
        cpu = {
          format = " {usage}%";
          tooltip = true;
        };
        memory = {
          format = " {}%";
        };
        backlight = {
          format = "{icon} {percent}%";
          format-icons = ["󰃞" "󰃟" "󰃠"];
        };
        battery = {
          states = {
            warning = 30;
            critical = 15;
          };
          format = "{icon} {capacity}%";
          format-charging = "󰂄 {capacity}%";
          format-plugged = " {capacity}%";
          format-icons = ["󰂃" "󰁺" "󰁻" "󰁼" "󰁽" "󰁾" "󰁿" "󰂀" "󰂁" "󰂂" "󰁹"];
        };
        pulseaudio = {
          format = "{icon} {volume}%";
          format-bluetooth = "{icon} {volume}%";
          format-muted = "󰝟 muted";
          format-icons = {
            headphone = "";
            default = ["" "" ""];
          };
          on-click = "${pkgs.pavucontrol}/bin/pavucontrol";
        };
      };
    };
    style = ''
      * {
        border: none;
        border-radius: 0;
        font-family: "JetBrainsMono Nerd Font", monospace;
        font-size: 13px;
        min-height: 0;
      }
      window#waybar {
        background-color: rgba(26, 27, 38, 0.88);
        color: #c0caf5;
        border-bottom: 2px solid rgba(122, 162, 247, 0.35);
      }
      #workspaces button {
        padding: 0 8px;
        color: #7982a9;
        background: transparent;
        border-radius: 4px;
        margin: 4px 2px;
      }
      #workspaces button.active {
        color: #ffffff;
        background-color: #3b4261;
        font-weight: bold;
      }
      #workspaces button.urgent {
        background-color: #f7768e;
        color: #1a1b26;
      }
      #window {
        color: #bb9af7;
        font-weight: 500;
        padding: 0 10px;
      }
      #clock, #battery, #cpu, #memory, #backlight, #pulseaudio, #tray {
        padding: 0 10px;
        margin: 4px 2px;
        border-radius: 6px;
        background-color: #24283b;
        color: #a9b1d6;
      }
      #pulseaudio.muted {
        background-color: #f7768e;
        color: #1a1b26;
      }
      #battery.charging, #battery.plugged {
        color: #9ece6a;
      }
      #battery.warning:not(.charging) {
        color: #e0af68;
      }
      #battery.critical:not(.charging) {
        background-color: #f7768e;
        color: #1a1b26;
      }
    '';
  };

  services.mako = {
    enable = true;
    settings = {
      font = "JetBrainsMono Nerd Font 10";
      background-color = "#1a1b26ee";
      text-color = "#c0caf5";
      border-color = "#7aa2f7";
      border-radius = 8;
      border-size = 2;
      default-timeout = 5000;
    };
  };

  programs.rofi = {
    enable = true;
  };

  home.packages = with pkgs; [
    brightnessctl
    polkit_gnome
    libnotify
    wireplumber
  ];
}
