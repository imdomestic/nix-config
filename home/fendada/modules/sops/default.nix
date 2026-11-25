{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: {
  imports = [inputs.sops-nix.homeManagerModules.sops];

  sops.age = {
    sshKeyPaths = ["${config.home.homeDirectory}/.ssh/id_ed25519"];
    keyFile = "${config.home.homeDirectory}/.config/sops/age/keys.txt";
  };

  # 上游的 darwin 激活步骤 bootout 不带 --wait，旧 job 还没卸完就 bootstrap，
  # 偶发 "Bootstrap failed: 5: Input/output error" 中断整个 switch；
  # 同样两步，像 Home Manager 自己的 launchd 步骤那样等 bootout 完成。
  home.activation.sops-nix = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin (lib.mkForce (
    lib.hm.dag.entryAfter ["setupLaunchAgents"] ''
      /bin/launchctl bootout --wait gui/$(id -u ${config.home.username})/org.nix-community.home.sops-nix || true
      /bin/launchctl bootstrap gui/$(id -u ${config.home.username}) ${config.home.homeDirectory}/Library/LaunchAgents/org.nix-community.home.sops-nix.plist
    ''
  ));
}
