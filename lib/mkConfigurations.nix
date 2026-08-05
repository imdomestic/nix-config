{inputs}: {hosts}: let
  lib = inputs.nixpkgs.lib;
  myHost = import ./my-host.nix;
  defaultNixpkgsConfig = {
    allowUnfree = true;
    allowUnfreePredicate = _: true;
  };

  mkSpecialArgs = hostName: host: let
    hostSystem = host.system or (throw "Host ${hostName} must define a system");
    pkgsUnstable = import inputs.nixpkgs-unstable {
      system = hostSystem;
      overlays = (host.overlays or []) ++ [inputs.nur.overlays.default];
      config = defaultNixpkgsConfig;
    };
  in
    {
      # `system` and `inputs` stay specialArgs because base profiles use them
      # in `imports`, which cannot depend on config. Everything else lives in
      # `config.my.host` (see modules/shared/host-options.nix).
      inherit inputs;
      system = hostSystem;
      "pkgs-unstable" = pkgsUnstable;
    }
    // (host.extraSpecialArgs or {});

  # No home-manager module here on purpose. Homes are standalone
  # `homeConfigurations` (lib/mkHomeConfigurations.nix) on every host, NixOS and
  # darwin alike, so `nixos-rebuild switch` never rebuilds a user's home and a
  # user can re-activate their own without touching the machine.
  mkModules = hostName: host:
    myHost.mkModules {inherit hostName host;}
    ++ lib.unique (
      (host.profiles or [])
      ++ (host.modules or [])
      ++ (host.hardwareModules or [])
      ++ (host.externalModules or [])
      ++ (host.extraModules or [])
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
      modules = mkModules hostName host;
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
