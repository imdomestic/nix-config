# WeChat's Linux client in a VM, driven by wxdesk. maxx doesn't use it
# since the bot's account was restricted: docs/decisions.md#wxdesk-vm; how
# to run it: docs/runbooks/wxdesk-vm.md.
{config, ...}: let
  secret = name: config.sops.secrets."wxdesk/${name}".path;
in {
  # A deploy doesn't restart the VM, so a change to these reaches the guest
  # when wxdesk-vm is next started.
  sops.secrets = {
    # What wxdesk's clients send first.
    "wxdesk/token".sopsFile = ../../secrets/hosts/tank-max.yaml;
    # WXDESK_GROUP=<the group's name>, WXDESK_ME=maxx.
    "wxdesk/env".sopsFile = ../../secrets/hosts/tank-max.yaml;
  };

  services.wxdesk-vm = {
    enable = true;
    tokenFile = secret "token";
    environmentFile = secret "env";
  };
}
