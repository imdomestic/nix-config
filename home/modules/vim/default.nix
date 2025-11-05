{pkgs, ...}: {
  programs.vim = {
    enable = true;
    plugins = with pkgs.vimPlugins; [
      nerdtree
      lightline-vim
      iceberg-vim
      haskell-vim
      wildfire-vim
      vim-easymotion
      vim-surround
    ];
    extraConfig = builtins.readFile ./config.vim;
  };
}
