{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;
  defaultNixpkgsConfig = {
    allowUnfree = true;
    allowUnfreePredicate = _: true;
  };

  mkSpecialArgs = hostName: host: let
    sysman = host.systemManager or {};
    hostUsers = host.users or {};
    usernames =
      if host ? usernames
      then host.usernames
      else builtins.attrNames hostUsers;
    hostSystem = host.system or (throw "Host ${hostName} must define a system");
    pkgsUnstable =
      import inputs.nixpkgs-unstable {
        system = hostSystem;
        overlays = (sysman.overlays or []) ++ [inputs.nur.overlays.default];
        config = defaultNixpkgsConfig;
      };
  in
    {
      inherit inputs hostName host hostUsers usernames;
      hostname = hostName;
      hostRoles = host.roles or [];
      system = hostSystem;
      pkgsUnstable = pkgsUnstable;
      "pkgs-unstable" = pkgsUnstable;
    }
    // (sysman.extraSpecialArgs or {});

  mkModules = hostName: host: let
    sysman = host.systemManager or {};
    hostSystem = host.system or (throw "Host ${hostName} must define a system");
    hostPlatform = sysman.hostPlatform or hostSystem;
    platformModule = {lib, ...}: {
      nixpkgs.hostPlatform = lib.mkDefault hostPlatform;
    };
    moduleList =
      (sysman.profiles or [])
      ++ (sysman.modules or [])
      ++ (sysman.extraModules or []);
  in
    [platformModule] ++ moduleList;

  mkSystemConfig = hostName: host: let
    sysman = host.systemManager or {};
    hostSystem = host.system or (throw "Host ${hostName} must define a system");
    _ =
      lib.assertMsg (lib.hasInfix "linux" hostSystem)
      "system-manager configs are only supported for Linux hosts (${hostName})";
  in
    inputs.system-manager.lib.makeSystemConfig {
      modules = mkModules hostName host;
      overlays = sysman.overlays or [];
      extraSpecialArgs = mkSpecialArgs hostName host;
    };

  hostList = lib.mapAttrsToList (name: value: {inherit name value;}) hosts;
  systemManagerHosts =
    lib.filter
    (
      hostEntry: let
        sysman = hostEntry.value.systemManager or {};
      in
        sysman.enable or false
    )
    hostList;

  perHostAttrs = hostEntry: let
    hostName = hostEntry.name;
    hostSystem = hostEntry.value.system or (throw "Host ${hostName} must define a system");
    cfg = mkSystemConfig hostName hostEntry.value;
    attrs = [
      (lib.setAttrByPath [hostName] cfg)
      (lib.setAttrByPath ["hosts" hostName] cfg)
      (lib.setAttrByPath [hostSystem hostName] cfg)
      (lib.setAttrByPath [hostSystem "hosts" hostName] cfg)
    ];
  in
    lib.foldl' lib.recursiveUpdate {} attrs;
in
  lib.foldl'
  (acc: hostEntry: lib.recursiveUpdate acc (perHostAttrs hostEntry))
  {}
  systemManagerHosts
