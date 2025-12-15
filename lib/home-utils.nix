{inputs}: let
  lib = inputs.nixpkgs.lib;
  defaultNixpkgsConfig = {
    allowUnfree = true;
    allowUnfreePredicate = _: true;
  };
in {
  mkHomeSpec = {
    host,
    hostName,
    userName,
    user,
  }: let
    home = user.home or {};
    system = home.system or host.system;
    overlays = lib.unique (
      (home.overlays or [])
      ++ (host.homeOverlays or [])
      ++ [inputs.nur.overlays.default]
    );
    pkgs = import inputs.nixpkgs {
      inherit system overlays;
      config = home.nixpkgsConfig or defaultNixpkgsConfig;
    };
    modules =
      (home.profiles or [])
      ++ (home.modules or [])
      ++ (home.extraModules or []);
    extraImports = home.extraImports or [];
    extraSpecialArgs = home.extraSpecialArgs or {};
    specialArgs =
      {
        inherit inputs system userName;
        username = userName;
        hostName = hostName;
        hostname = hostName;
        roles = host.roles or [];
      }
      // extraSpecialArgs;
  in {
    inherit pkgs modules extraImports specialArgs system;
  };
}
