{
  config,
  pkgs,
  ...
}: let
  hostname = config.my.host.name;
in {
  programs.walker = {
    package = pkgs.walker;
    # 原本写的是 "b660",而这个 fleet 里根本没有叫 b660 的机器(是 b650)——
    # 也就是说 walker 从来没在那台上开起来过。7540u 已经退役删掉了。
    enable = hostname == "b650";
    runAsService = true;

    # All options from the config.json can be used here.
    config = {
      # search.placeholder = "Example";
      ui.fullscreen = false;
      list = {
        height = 200;
      };
      websearch.prefix = "?";
      switcher.prefix = "/";
    };
  };
}
