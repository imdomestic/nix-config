{
  config,
  lib,
  pkgs,
  ...
}: let
  windowsEntry = pkgs.writeText "encore-windows.conf" config.boot.loader.systemd-boot.extraEntries."windows.conf";
  prepareWindowsLoader = ''
    ${pkgs.util-linux}/bin/mountpoint -q /efi
    ${pkgs.util-linux}/bin/mountpoint -q /boot
    windowsBoot=/efi/EFI/Microsoft/Boot
    if [ -f "$windowsBoot/bootmgfw.efi" ]; then
      ${pkgs.coreutils}/bin/mv -f "$windowsBoot/bootmgfw.efi" "$windowsBoot/windows.efi"
    fi
    test -s "$windowsBoot/windows.efi"
    windowsFallback=/efi/EFI/Boot
    if [ -f "$windowsFallback/bootx64.efi" ] && ${pkgs.diffutils}/bin/cmp -s "$windowsFallback/bootx64.efi" "$windowsBoot/windows.efi"; then
      ${pkgs.coreutils}/bin/mv -f "$windowsFallback/bootx64.efi" "$windowsFallback/windows.efi"
    fi
    # systemd-boot 拷贝 Windows 文件到 /boot（XBOOTLDR 分区），
    # 确保无论 systemd-boot 从 $BOOT 还是 ESP 读取都能找到 Windows 启动文件。
    ${pkgs.coreutils}/bin/install -d /boot/EFI/Microsoft /boot/loader/entries
    ${pkgs.coreutils}/bin/cp -r /efi/EFI/Microsoft/. /boot/EFI/Microsoft/
    ${pkgs.coreutils}/bin/install -m 0600 ${windowsEntry} /boot/loader/entries/windows.conf
    # 确保 /efi/EFI/BOOT/BOOTX64.EFI 是最新的 systemd-boot 引导二进制（华硕固件默认执行此 fallback 路径）
    ${pkgs.coreutils}/bin/install -D -m 0755 ${config.systemd.package}/lib/systemd/boot/efi/systemd-bootx64.efi /efi/EFI/BOOT/BOOTX64.EFI
  '';
in {
  imports = [
    ../../system/modules/keyd
    ../../system/modules/nerdfonts
  ];

  boot.kernel.sysctl = {
    # 禁用 Alder Lake 等现代 Intel CPU 上的 split lock 延迟惩罚（默认强制 sleep 10ms），
    # 解决 Bambu Studio 等含未对齐原子锁的程序在拖动模型/UI 交互时的严重卡顿
    "kernel.split_lock_mitigate" = 0;

    # 配合 zramSwap 调优：积极换出匿名页进压缩池，避免抢占文件页缓存导致桌面卡顿
    "vm.swappiness" = 150;
    "vm.page-cluster" = 0; # zram 按单页解压，禁用磁盘式的顺序预读
    "vm.watermark_scale_factor" = 125; # 提前启动后台回收
  };

  # 双重 Swap 防线：优先走 12 GiB 高速 zram 压缩内存，再以 8 GiB 物理磁盘 Swapfile 兜底
  zramSwap = {
    enable = true;
    memoryPercent = 50; # 约 11.5~12 GiB
    algorithm = "zstd";
    priority = 100; # 优先换入 zram
  };

  swapDevices = [
    {
      device = "/var/lib/swapfile";
      size = 8 * 1024; # 8 GiB
      priority = 10; # 低优先级，仅在 zram 耗尽时溢出到磁盘
    }
  ];

  # 限制 Nix 构建并发为最大全大核
  # i7-12700H (6P + 8E): 单包内部最大 12 线程（吃满全部 6 个 P-Core 性能大核）
  nix.settings = {
    cores = 12;
    max-jobs = 2;
  };

  # 放宽后台 home-sync 内存限制，防止软件包更新回落本地编译时撞上默认 3G cgroup 内存墙
  systemd.services.home-sync.serviceConfig.MemoryMax = lib.mkForce "16G";

  # 从 GRUB 切换为 systemd-boot 与双系统兼容细节见 docs/decisions.md#encore-systemd-boot。
  boot.loader = {
    timeout = 5;
    grub.enable = false;
    systemd-boot = {
      enable = true;
      configurationLimit = 5;
      editor = false;
      xbootldrMountPoint = "/boot";
      extraInstallCommands = prepareWindowsLoader;
      extraEntries."windows.conf" = ''
        title Windows
        efi /EFI/Microsoft/Boot/windows.efi
        sort-key o_windows
      '';
    };
    efi = {
      canTouchEfiVariables = false;
      efiSysMountPoint = "/efi";
    };
  };

  networking = {
    networkmanager = {
      enable = true;
      wifi.powersave = false;
      ensureProfiles = {
        environmentFiles = ["/var/lib/NetworkManager/encore-wifi.env"];
        profiles.encore-wifi = {
          connection = {
            id = "encore-wifi";
            type = "wifi";
            autoconnect = true;
            autoconnect-retries = 0;
          };
          wifi = {
            mode = "infrastructure";
            ssid = "$INSTALLER_WIFI_SSID";
          };
          wifi-security = {
            key-mgmt = "wpa-psk";
            psk = "$INSTALLER_WIFI_PASSWORD";
          };
          ipv4.method = "auto";
          ipv6.method = "auto";
        };
      };
    };
    nftables.enable = true;
  };

  hardware = {
    graphics.enable = true;
    nvidia = {
      modesetting.enable = true;
      powerManagement.enable = false;
      open = true;
      nvidiaSettings = false;
      nvidiaPersistenced = true;
      package = config.boot.kernelPackages.nvidiaPackages.production;
    };
    nvidia-container-toolkit.enable = true;
  };
  nixpkgs.config.allowUnfree = true;
  virtualisation.podman.enable = true;

  my.inputMethod = "fcitx5";
  services = {
    tailscale.extraSetFlags = ["--hostname=${config.networking.hostName}"];
    displayManager.defaultSession = "hyprland";
    displayManager.gdm = {
      enable = true;
      autoSuspend = false;
    };
    # SSH 进来跑 mc-client 时桌面得已经有人登录，否则没有 DISPLAY 可借。
    # 新版 nixpkgs 把 autoLogin 从 gdm 子模块挪到了 displayManager 顶层。
    displayManager.autoLogin = {
      enable = true;
      user = "linwhite";
    };
    desktopManager.gnome.enable = true;
    switcherooControl.enable = true;
    pipewire = {
      enable = true;
      alsa.enable = true;
      pulse.enable = true;
    };
    logind.settings.Login = {
      HandleLidSwitch = "ignore";
      HandleLidSwitchExternalPower = "ignore";
      HandleLidSwitchDocked = "ignore";
      IdleAction = "ignore";
    };
    # 串流：Mac 上的 Moonlight 连这里。端口在 minecraft.nix 的 tailscale0 规则里放。
    sunshine = {
      enable = true;
      capSysAdmin = true; # GNOME Wayland 的 KMS 屏幕捕获需要此权限。
    };
    avahi = {
      enable = true;
      openFirewall = true;
      publish = {
        enable = true;
        addresses = true;
        workstation = true;
      };
    };
    # GNOME 优先用 Intel 渲染，但不能忽略 NVIDIA：HDMI 接在独显上。
    udev.extraRules = ''
      SUBSYSTEM=="drm", KERNEL=="card[0-9]*|renderD[0-9]*", ATTRS{vendor}=="0x8086", ATTRS{device}=="0x46a6", TAG+="mutter-device-preferred-primary"
    '';
  };
  systemd.sleep.settings.Sleep = {
    AllowSuspend = false;
    AllowHibernation = false;
    AllowHybridSleep = false;
    AllowSuspendThenHibernate = false;
  };
  systemd.targets = {
    sleep.enable = false;
    suspend.enable = false;
    hibernate.enable = false;
    hybrid-sleep.enable = false;
    suspend-then-hibernate.enable = false;
  };
  programs.dconf.profiles.user.databases = [
    {
      lockAll = true;
      settings."org/gnome/settings-daemon/plugins/power" = {
        sleep-inactive-ac-type = "nothing";
        sleep-inactive-battery-type = "nothing";
      };
    }
  ];
  systemd.services.encore-boot-entries = {
    description = "Keep the SSD and rescue USB boot entries";
    wantedBy = ["multi-user.target"];
    after = ["local-fs.target"];
    unitConfig = {
      ConditionPathIsMountPoint = "/sys/firmware/efi/efivars";
      RequiresMountsFor = ["/boot" "/efi"];
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "encore-boot-entries";
      StateDirectoryMode = "0700";
      UMask = "0077";
    };
    script =
      prepareWindowsLoader
      + ''
        test -s /efi/EFI/BOOT/BOOTX64.EFI
        shopt -s nullglob
        for variable in /sys/firmware/efi/efivars/Boot????-8be4df61-93ca-11d2-aa0d-00e098032b8c; do
          name=''${variable##*/}
          name=''${name%%-*}
          entry="$(${pkgs.efibootmgr}/bin/efibootdump "$name")"
          case "$entry" in
            "$name: "*"Windows Boot Manager HD(1,GPT,8762fad7-cfcb-4eae-8bf0-4315bef44901,"*)
              ${pkgs.coreutils}/bin/cp "$variable" "$STATE_DIRECTORY/$name"
              ${pkgs.efibootmgr}/bin/efibootmgr --bootnum "''${name#Boot}" --delete-bootnum
              ;;
            "$name: "*"UEFI:CD/DVD Drive BBS(129,,0x0)"|"$name: "*"UEFI:Removable Device BBS(130,,0x0)"|"$name: "*"UEFI:Network Device BBS(131,,0x0)")
              ${pkgs.coreutils}/bin/cp "$variable" "$STATE_DIRECTORY/$name"
              ${pkgs.efibootmgr}/bin/efibootmgr --bootnum "''${name#Boot}" --delete-bootnum
              ;;
          esac
        done
      '';
  };

  security = {
    rtkit.enable = true;
    sudo.wheelNeedsPassword = false;
  };
  users.users = {
    linwhite = {
      hashedPasswordFile = "/var/lib/user-passwords/linwhite";
      # Sunshine 要写 /dev/uinput 做输入回注
      extraGroups = ["uinput"];
    };
    hank.hashedPasswordFile = "/var/lib/user-passwords/hank";
  };
  programs = {
    zsh.enable = true;
    nix-index-database.comma.enable = true;
    hyprland = {
      enable = true;
      xwayland.enable = true;
    };
  };
  environment.systemPackages = with pkgs; [
    pciutils
    efibootmgr
    nvtopPackages.nvidia
    btop-cuda
  ];

  time.timeZone = "Asia/Tokyo";
  system.stateVersion = "26.05";
}
