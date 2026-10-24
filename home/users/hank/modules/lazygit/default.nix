{
  programs.lazygit = {
    enable = true;
    enableZshIntegration = false;
    settings.gui = {
      # 与 Hank 的 nixvim 同用 Evergarden Winter / Green。
      # https://github.com/evergardentheme/lazygit/blob/main/themes/evergarden-winter-green.yml
      theme = {
        activeBorderColor = ["#cae0a7" "bold"];
        inactiveBorderColor = ["#96b4aa"];
        optionsTextColor = ["#b2cfed"];
        selectedLineBgColor = ["#2d393d"];
        cherryPickedCommitBgColor = ["#323933"];
        cherryPickedCommitFgColor = ["#cae0a7"];
        unstagedChangesColor = ["#f57f82"];
        defaultFgColor = ["#f8f9e8"];
        searchingActiveBorderColor = ["#f5d098"];
      };
      authorColors."*" = "#96b4aa";
    };
  };
}
