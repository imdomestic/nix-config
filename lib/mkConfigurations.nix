{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;
  defaultNixpkgsConfig = {
    allowUnfree = true;
    allowUnfreePredicate = _: true;
  };

  mkSpecialArgs = hostName: host: let
    hostUsers = host.users or {};
    hostSystem = host.system or (throw "Host ${hostName} must define a system");
    usernames =
      if host ? usernames
      then host.usernames
      else builtins.attrNames hostUsers;
    pkgsUnstable = import inputs.nixpkgs-unstable {
      system = hostSystem;
      overlays = (host.overlays or []) ++ [inputs.nur.overlays.default];
      config = defaultNixpkgsConfig;
    };
  in
    {
      inherit inputs hostName hostUsers usernames;
      hostname = hostName;
      hostRoles = host.roles or [];
      system = hostSystem;
      host = host;
      pkgsUnstable = pkgsUnstable;
      "pkgs-unstable" = pkgsUnstable;
    }
    // (host.extraSpecialArgs or {});

  mkModules = host: let
    system = host.system or (throw "Host ${host} must define a system");
    isDarwin = lib.hasInfix "darwin" system;
    enableHomeManager =
      if host ? withHomeManager
      then host.withHomeManager
      else true;
    homeManagerModule =
      if enableHomeManager
      then
        if isDarwin
        then inputs.home-manager.darwinModules.home-manager
        else inputs.home-manager.nixosModules.home-manager
      else null;
  in
    lib.unique (
      (host.profiles or [])
      ++ (host.modules or [])
      ++ (host.hardwareModules or [])
      ++ (host.externalModules or [])
      ++ (host.extraModules or [])
      ++ lib.optional (homeManagerModule != null) homeManagerModule
    );

  mkSystem = hostName: host: let
    system = host.system or (throw "Host ${hostName} must define a system");
    isDarwin = lib.hasInfix "darwin" system;
    builder =
      if isDarwin
      then inputs.nix-darwin.lib.darwinSystem
      else inputs.nixpkgs.lib.nixosSystem;
  in
    builder {
      inherit system;
      modules = mkModules host;
      specialArgs = mkSpecialArgs hostName host;
    };

  hostList = lib.mapAttrsToList (name: value: {inherit name value;}) hosts;
  systemHosts = lib.filter (h: (h.value.kind or "system") != "home") hostList;
  linuxHosts = lib.filter (h: lib.hasInfix "linux" h.value.system) systemHosts;
  darwinHosts = lib.filter (h: lib.hasInfix "darwin" h.value.system) systemHosts;
in {
  nixosConfigurations = lib.listToAttrs (lib.map (h: {
      name = h.name;
      value = mkSystem h.name h.value;
    })
    linuxHosts);
  darwinConfigurations = lib.listToAttrs (lib.map (h: {
      name = h.name;
      value = mkSystem h.name h.value;
    })
    darwinHosts);
}
