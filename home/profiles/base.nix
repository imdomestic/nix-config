{
  pkgs,
  ...
}: {
  home.packages = with pkgs; [
    curl
    tmux
    ripgrep
    fd
    tree
    file
    which
    wget
    gnugrep
    gnused
    coreutils

    # archives
    zip
    xz
    unzip
    p7zip
    zstd
  ];

  programs.zsh = {
    enable = true;
  };

  programs.neovim = {
    enable = true;
    defaultEditor = true;
  };
}
