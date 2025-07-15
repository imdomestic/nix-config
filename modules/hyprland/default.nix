# This module is used in home-manager
{
  inputs,
  pkgs,
  hostname,
  ...
}: let
  lib = pkgs.lib;
in {
  programs.hyprpanel = {
    enable = hostname == "7540u" || hostname == "b660";
    settings = {
      layout = {
        "bar.layouts" = {
          "*" = {
            left = ["dashboard" "workspaces" "windowtitle"];
            middle = ["media"];
            right = [
              "ram"
              "volume"
              "systray"
              "clock"
              "notifications"
            ];
          };
        };
      };
      theme.font.size = "15";
      theme.name = "catppuccin_mocha";
      bar = {
        launcher.autoDetectIcon = true;
        workspaces = {
          show_icons = true;
          monitorSpecific = false;
        };
        clock = {
          format = "%H:%M";
          icon = "";
        };
      };
      theme.bar = {
        transparent = false;
        outer_spacing = "0.2em";
      };
      theme.osd.orientation = "horizontal";
      theme.osd.location = "bottom";
      theme.osd.margins = "0px 0px 20px 0px";
      menus.dashboard.shortcuts.left.shortcut1.command = "zen";
      menus.dashboard.shortcuts.left.shortcut2.command = "spotify";
      menus.dashboard.shortcuts.left.shortcut4.icon = "";
      menus.dashboard.shortcuts.left.shortcut4.command = "nautilus";
      menus.dashboard.directories.enabled = false;
      menus.dashboard.stats.interval = 1000;
      # menus.dashboard.stats.enable_gpu = true;
      menus.clock = {
        time = {
          military = true;
        };
        weather.unit = "metric";
      };
    };
  };

  services.hyprpaper = {
    enable = true;
    settings = {
      ipc = "off";
      splash = false;
      preload = [
        "/home/hank/wallpapers/nixos-stroke-4k.png"
        "/home/hank/wallpapers/nixos-blue-4k.png"
        "/home/hank/wallpapers/grid.png"
      ];

      wallpaper =
        if hostname == "7540u"
        then [
          "DP-2,/home/hank/wallpapers/nixos-blue-4k.png"
          "eDP-1,/home/hank/wallpapers/grid.png"
        ]
        else if hostname == "H610"
        then [
          "DP-2,/home/hank/wallpapers/nixos-stroke-4k.png"
        ]
        else if hostname == "tank"
        then [
          "DP-2,/home/hank/wallpapers/nixos-blue-4k.png"
        ]
        else if hostname == "b660"
        then [
          "DP-2,/home/hank/wallpapers/nixos-blue-4k.png"
        ]
        else [];
    };
  };
  home.pointerCursor = {
    package = pkgs.vanilla-dmz;
    name = "Vanilla-DMZ";
    hyprcursor.enable = true;
  };
  home.packages = with pkgs; [
    nwg-look
    pavucontrol
    grimblast
    wl-clipboard
    playerctl
    hyprpanel
  ];
  wayland.windowManager.hyprland.systemd.variables = ["--all"];
  wayland.windowManager.hyprland = {
    enable = true; # enable Hyprland
    xwayland.enable = true;
    settings = {
      general = {
        border_size = 0;
        gaps_in = 5;
        gaps_out = 10;
        resize_on_border = true;
        extend_border_grab_area = 10;
      };
      decoration = {
        rounding = 8;
        blur = {
          enabled = true;
          size = 5;
          passes = 3;
          new_optimizations = true;
        };
        shadow = {
          enabled = false;
          ignore_window = true;
          offset = "2 2";
          range = 4;
          render_power = 2;
        };
      };
      animations = {
        enabled = false;
      };
      input = {
        sensitivity = -0.9;
        follow_mouse = 1;
        touchpad = {
          scroll_factor = 0.1;
        };
      };
      "$mod" = "SUPER";
      monitor =
        if hostname == "7540u"
        then [
          "DP-2,3840x2160@240,0x0,1.5"
          "eDP-1,1920x1200@60.03,1920x0,1.25"
        ]
        else if hostname == "H610"
        then [
          "DP-2,3440x1440@144,0x0,1"
        ]
        else if hostname == "tank"
        then [
          "DP-2,3440x1440@144,0x0,1"
        ]
        else if hostname == "b660"
        then [
          "DP-2,3840x2160@240,0x0,1.5"
        ]
        else if hostname == "rpi4"
        then [
          "HDMI-A-1,1920x1080@120,0x0,1"
        ]
        else [
        ];
      exec-once =
        [
          "hyprctl setcursor \"Vanilla-DMZ\" 24"
          "fcitx5 -d"
        ]
        ++ (
          if (hostname == "b660" || hostname == "7540u")
          then ["hyprpanel"]
          else []
        );
      # l -> do stuff even when locked
      # e -> repeats when key is held
      bindle = [
        ", XF86AudioRaiseVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%+"
        ", XF86AudioLowerVolume, exec, wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"
        ", XF86MonBrightnessUp, exec, brightnessctl s 5%+"
        ", XF86MonBrightnessDown, exec, brightnessctl s 5%-"
        ", XF86Search, exec, walker"
      ];
      bindl = [
        ", XF86AudioMute, exec, wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"
        ", XF86AudioPlay, exec, playerctl play-pause" # the stupid key is called play , but it toggles
        ", XF86AudioNext, exec, playerctl next"
        ", XF86AudioPrev, exec, playerctl previous"
      ];
      bindm = [
        "$mod, mouse:272, movewindow"
        "$mod, mouse:273, resizewindow"
        "$mod ALT, mouse:272, resizewindow"
      ];
      bind =
        [
          "$mod, Q, killactive,"
          "$mod SHIFT, Q, exit,"
          "$mod, F, fullscreen"
          "$mod, Space, togglefloating"
          "$mod SHIFT, S, exec, grimblast copy area"
          "$mod, Return, exec, ghostty"
          "$mod, I, exec, gnome-control-center"
          "$mod, E, exec, nautilus"
          "$mod, W, exec, zen"
          "$mod, left, resizeactive, -20 0"
          "$mod, right, resizeactive, 20 0"
          "$mod, up, resizeactive, 0 -20"
          "$mod, down, resizeactive, 0 20"
          "$mod, J, movefocus, d"
          "$mod, K, movefocus, u"
          "$mod, H, movefocus, l"
          "$mod, L, movefocus, r"
          # "$mod, A, exec, killall rofi || rofi -show drun -theme ~/.config/rofi/config.rasi"
          "$mod, P, exec, pavucontrol"
          "$mod SHIFT, H, movewindow, l"
          "$mod SHIFT, L, movewindow, r"
          "$mod SHIFT, K, movewindow, u"
          "$mod SHIFT, J, movewindow, d"
          "$mod SHIFT, Return, togglespecialworkspace"
        ]
        ++ (
          builtins.concatLists (builtins.genList (
              i: let
                ws = i + 1;
              in [
                "$mod, ${toString ws}, workspace, ${toString ws}"
                "$mod SHIFT, ${toString ws}, movetoworkspace, ${toString ws}"
              ]
            )
            9)
        )
        ++ (
          if (hostname == "b660" || hostname == "7540u")
          then [
            "$mod, A, exec, walker"
          ]
          else [
            "$mod, A, exec, killall tofi-drun || tofi-drun --drun-launch=true"
          ]
        );
    };
    extraConfig = ''
      device {
          name = syna8019:00-06cb:ce68-touchpad
          sensitivity = -0
          natural_scroll = true
      }
      device {
          name = ninjutso-ninjutso-sora-v2-mouse
          sensitivity = -0.9
      }
    '';
  };
}
