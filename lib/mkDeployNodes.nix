# lib/mkDeployNodes.nix
{inputs}: {
  hosts,
  nixosConfigurations,
  homeConfigurations,
}: let
  inherit (inputs.nixpkgs) lib;
  deploy-rs = inputs.deploy-rs;

  # Homes are standalone closures now (see lib/mkConfigurations.nix), so a
  # system deploy no longer drags them along. Give every user of a deployable
  # host their own profile instead, otherwise accounts whose owner never logs in
  # to run `home-manager` themselves would silently stop being updated.
  mkHomeProfiles = name: hostConfig: let
    sshUser = hostConfig.sshUser or "root";
    mkProfile = userName: _: {
      name = "home-${userName}";
      value = {
        user = userName;
        inherit sshUser;
        # deploy-rs builds the activation command as `<sudo> <user> <script>`,
        # and its default `sudo -u` keeps the ssh user's HOME. Home Manager's
        # activation script resolves every path relative to $HOME, so without
        # -H it would write the user's home into /root.
        sudo = "sudo -H -u";
        path =
          deploy-rs.lib.${hostConfig.system}.activate.home-manager
          homeConfigurations."hosts/${name}/${userName}";
      };
    };
  in
    lib.mapAttrs' mkProfile (hostConfig.users or {});
in
  lib.mapAttrs (
    name: hostConfig: let
      isDeployable = (hostConfig ? ip) && (builtins.hasAttr name nixosConfigurations);
      homeProfiles = mkHomeProfiles name hostConfig;
    in
      if isDeployable
      then {
        hostname = hostConfig.ip;

        fastConnection = false;
        autoRollback = true;
        magicRollback = true;
        activationTimeout = 120;

        # System first: a home generation may reference users, groups or
        # services the new system introduces.
        profilesOrder = ["system"] ++ lib.attrNames homeProfiles;

        profiles =
          {
            system = {
              user = "root";
              sshUser = hostConfig.sshUser or "root";
              path = deploy-rs.lib.${hostConfig.system}.activate.nixos nixosConfigurations.${name};
            };
          }
          // homeProfiles;
      }
      else {}
  )
  (lib.filterAttrs (n: v: (v ? ip) && (v.kind or "nixos" == "nixos")) hosts)
