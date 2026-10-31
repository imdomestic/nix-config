{
  config,
  inputs,
  lib,
  ...
}: let
  # Headscale names each person <account>@imdomestic.com.
  login = account: "tailscale:${account}@imdomestic.com";
  accounts = config.my.host.usernames;
in {
  imports = [inputs.rex.nixosModules.default];

  # One Rex server per account, each started as that account; every caller
  # reaches only their own. docs/rex.md#login-server.
  services.rex.loginServer = {
    enable = true;
    accounts = lib.genAttrs accounts (account: {principals = [(login account)];});
    defaults = lib.listToAttrs (map (account: lib.nameValuePair (login account) account) accounts);
    extraListen = ["tailnet://:7297"];
  };

  networking.firewall.interfaces.tailscale0.allowedTCPPorts = [7297];
}
