{inputs}: let
  lib = inputs.nixpkgs.lib;
  myHost = import ./my-host.nix;
  defaultNixpkgsConfig = {
    allowUnfree = true;
    allowUnfreePredicate = _: true;
  };
in rec {
  # One nixpkgs/nixpkgs-unstable eval shared by every user of a host; only
  # users overriding home.{system,overlays,nixpkgsConfig} pay for their own.
  mkBasePkgs = {host}: let
    system = host.system;
    overlays = lib.unique (
      (host.homeOverlays or [])
      ++ [inputs.nur.overlays.default]
    );
  in {
    pkgs = import inputs.nixpkgs {
      inherit system overlays;
      config = defaultNixpkgsConfig;
    };
    pkgsUnstable = import inputs.nixpkgs-unstable {
      inherit system overlays;
      config = defaultNixpkgsConfig;
    };
  };

  mkHomeSpec = {
    host,
    hostName,
    userName,
    user,
    basePkgs ? null,
  }: let
    home = user.home or {};
    system = home.system or host.system;
    useBase =
      basePkgs
      != null
      && !(home ? system)
      && !(home ? overlays)
      && !(home ? nixpkgsConfig);
    overlays = lib.unique (
      (home.overlays or [])
      ++ (host.homeOverlays or [])
      ++ [inputs.nur.overlays.default]
    );
    pkgs =
      if useBase
      then basePkgs.pkgs
      else
        import inputs.nixpkgs {
          inherit system overlays;
          config = home.nixpkgsConfig or defaultNixpkgsConfig;
        };
    pkgsUnstable =
      if useBase
      then basePkgs.pkgsUnstable
      else
        import inputs.nixpkgs-unstable {
          inherit system overlays;
          config = home.nixpkgsConfig or defaultNixpkgsConfig;
        };
    modules =
      myHost.mkModules {inherit hostName host system;}
      # Single injection point for the account name; everything else reads
      # `config.home.username` / `config.home.homeDirectory`.
      ++ [{home.username = userName;}]
      ++ (home.profiles or [])
      ++ (home.modules or [])
      ++ (home.extraModules or []);
    extraImports = home.extraImports or [];
    extraSpecialArgs = home.extraSpecialArgs or {};
    # `inputs` and `system` stay specialArgs because they are used in
    # `imports`; host/user metadata lives in `config.my.host` / `config.home`.
    specialArgs =
      {
        inherit inputs system;
        "pkgs-unstable" = pkgsUnstable;
      }
      // extraSpecialArgs;
  in {
    inherit pkgs modules extraImports specialArgs system;
  };
}
