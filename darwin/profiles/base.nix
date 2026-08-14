{
  lib,
  pkgs,
  config,
  system,
  ...
}: {
  imports = [
    ../../nixos/modules/nix.nix
    ../../nixos/modules/users.nix
    ../../nixos/modules/home-manager-cli.nix
  ];

  # Host metadata comes from config.my.host (see modules/shared/host-options.nix);
  # legacy module args are bridged centrally in lib/mkConfigurations.nix.
  networking.hostName = lib.mkDefault config.my.host.name;
  nixpkgs.hostPlatform = lib.mkDefault system;

  # nix-darwin 默认往 /etc/zshrc 里写 `autoload -U compinit && compinit`,而
  # home-manager 生成的 .zshrc 里还有一个。两次之间 home-manager 往 fpath 里塞了
  # 插件目录,所以两边数到的补全文件数不同 —— 而 compinit 复用 dump 的条件正是
  # "dump 里记的文件数 == 这次数到的",于是它俩永远互相判定对方写的 ~/.zcompdump
  # 失效,每开一个 shell 都要重扫三千多个文件重写一遍。实测这一项 125ms。
  #
  # home-manager 那边(programs.zsh.completionInit)已经把 compinit 接管了,还给它
  # 配了独立的 dump 文件,所以系统这份纯属重复劳动,关掉。
  # (这个开关只管 compinit;/etc/zshrc 里的 bashcompinit 是独立的,仍然在。)
  programs.zsh.enableCompletion = false;

  # 同样是 /etc/zshrc 里的:`promptinit && prompt suse`。starship 会在之后把提示符
  # 整个换掉,这段只是白跑。
  programs.zsh.promptInit = "";

  # 把 nix 的 zsh 放进 /etc/shells,这样它才能被 chsh 选成登录 shell。
  # 光有 users.nix 里的 `shell = pkgs.zsh` 在 macOS 上是不生效的:nix-darwin 只对
  # users.knownUsers 里的账户改 shell,而 hank 是 macOS 自己建的既有账户。
  environment.shells = [pkgs.zsh];
}
