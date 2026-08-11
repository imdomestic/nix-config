{inputs}: let
  nixosProfiles = import ../../profiles/default.nix;
  homeProfiles = import ../../../home/profiles/default.nix;
  userModules = import ../../../home/users/default.nix {inherit inputs;};
in {
  system = "x86_64-linux";
  kind = "nixos";
  # 第二份监控。**和 tank 配对的意义全在于故障域不同** —— 2026-08-10 tank 那边
  # 停电一整天,h610 全程在线。放同一个屋子里等于还是一份。
  roles = ["server" "monitor"];
  tsIp = "100.64.0.3";
  ip = "10.0.0.5";
  sshUser = "root";

  profiles = with nixosProfiles; [
    base
    server
  ];

  modules = [
    ./system.nix
    ./hardware-configuration.nix
  ];

  externalModules = [
    # inputs.headplane.nixosModules.headplane
    inputs.max.nixosModules.max
    inputs.qq-bot.nixosModules.qq-deepseek-bot
  ];

  users = {
    hank = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.hank.module
          userModules.hank.dev
        ];
      };
    };
    genisys = {
      home = {
        profiles = with homeProfiles; [
          core
        ];
        modules = [
          userModules.genisys.module
        ];
      };
    };
    linwhite = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.linwhite.module
        ];
      };
    };
    kenneth = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.kenneth.module
        ];
      };
    };
    fendada = {
      home = {
        profiles = with homeProfiles; [
          core
          base
        ];
        modules = [
          userModules.fendada.module
        ];
      };
    };
  };
}
