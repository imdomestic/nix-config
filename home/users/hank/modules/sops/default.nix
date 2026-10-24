{
  config,
  inputs,
  ...
}: {
  imports = [inputs.sops-nix.homeManagerModules.sops];

  # 与 .sops.yaml 的管理员收件人一致，运行时从用户的 SSH key 派生 age key。
  sops.age.sshKeyPaths = ["${config.home.homeDirectory}/.ssh/id_ed25519"];
}
