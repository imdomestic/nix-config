{lib, ...}: let
  unitNames = [
    "minecraft-server-GTL"
    "minecraft-server-bedrock-proxy"
    "minecraft-server-bingo"
    "minecraft-server-lobby"
    "minecraft-server-proxy"
    "minecraft-server-speedrun"
  ];
  disableUnit = _: {
    enable = lib.mkForce false;
    wantedBy = lib.mkForce [];
  };
in {
  systemd.services = lib.genAttrs unitNames disableUnit;
  systemd.sockets = lib.genAttrs unitNames disableUnit;

  # 固定系统 GC root；原归档目录中的运行依赖 GC roots 继续保留。
  systemd.tmpfiles.rules = [
    "L /nix/var/nix/gcroots/chorus-legacy-system - root root - /nix/store/9iccjri350m0ckpqli6j3ag5j3c88chm-nixos-system-encore-26.05.20260911.21a67dc"
    "L /nix/var/nix/gcroots/chorus-legacy-extra-system - root root - /nix/store/wdn9y5fv1zmmqvlg8y3130r6kjaszncd-nixos-system-encore-26.05.20260911.21a67dc"
  ];
}
