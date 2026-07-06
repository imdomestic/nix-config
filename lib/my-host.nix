# Wiring for `config.my.host`: the options module plus an assignment module
# built from a host registry entry. Used by every builder in lib/ so all
# evaluations (nixos, darwin, home-manager, system-manager) share one schema.
let
  optionsModule = ../modules/shared/host-options.nix;

  mkAssignModule = {
    hostName,
    host,
    # home-manager evals may resolve a different system than the host itself
    system ? host.system,
  }: {
    my.host =
      {
        name = hostName;
        inherit system;
        roles = host.roles or [];
        users = host.users or {};
        homeOverlays = host.homeOverlays or [];
      }
      // (
        if host ? usernames
        then {usernames = host.usernames;}
        else {}
      );
  };
in {
  inherit optionsModule mkAssignModule;
  mkModules = args: [optionsModule (mkAssignModule args)];
}
