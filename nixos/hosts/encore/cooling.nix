{
  config,
  lib,
  ...
}: let
  fanCurves = lib.concatMapStringsSep "\n" (fan: ''
    (
      fan: ${fan},
      pwm: (89, 128, 166, 204, 230, 255, 255, 255),
      temp: (30, 40, 50, 60, 65, 70, 80, 90),
      enabled: true,
    ),
  '') ["CPU" "GPU"];
  powerLimits = sustained: burst: {
    Update_Rate_s = 5;
    PL1_Tdp_W = sustained;
    PL1_Duration_s = 2;
    PL2_Tdp_W = burst;
    PL2_Duration_S = 0.002;
    Trip_Temp_C = 80; # 温度优先；配置和测量见 docs/encore-cooling.md。
    Disable_BDPROCHOT = false;
  };
in {
  services.asusd = {
    enable = true;
    # 电源档位和 CPU EPP 由 power-profiles-daemon 管理。
    asusdConfig.text = ''
      (
        charge_control_end_threshold: 100,
        base_charge_control_end_threshold: 100,
        disable_nvidia_powerd_on_battery: false,
        ac_command: "",
        bat_command: "",
        platform_profile_linked_epp: false,
        platform_profile_on_battery: Quiet,
        change_platform_profile_on_battery: false,
        platform_profile_on_ac: Balanced,
        change_platform_profile_on_ac: false,
        profile_quiet_epp: Power,
        profile_balanced_epp: BalancePower,
        profile_custom_epp: Performance,
        profile_performance_epp: Performance,
        ac_profile_tunings: {},
        dc_profile_tunings: {},
        armoury_settings: {},
      )
    '';
    fanCurvesConfig.text = ''
      (
        profiles: (
          balanced: [${fanCurves}],
          performance: [${fanCurves}],
          quiet: [${fanCurves}],
          custom: [],
        ),
      )
    '';
  };

  services.throttled = {
    enable = true;
    extraConfig = lib.generators.toINI {} {
      GENERAL = {
        Enabled = true;
        Autoreload = true;
        Sysfs_Power_Path = "/sys/class/power_supply/AC*/online";
      };
      AC = powerLimits 35 45;
      BATTERY = powerLimits 25 35;
    };
  };

  systemd.services.asusd = {
    wantedBy = ["multi-user.target"];
    restartTriggers = [
      config.environment.etc."asusd/asusd.ron".source
      config.environment.etc."asusd/fan_curves.ron".source
    ];
  };
  systemd.services.throttled = {
    description = "CPU power and temperature limits";
    after = ["systemd-modules-load.service"];
    requires = ["systemd-modules-load.service"];
    restartTriggers = [config.environment.etc."throttled.conf".source];
    serviceConfig = {
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
