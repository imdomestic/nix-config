{
  hostname,
  pkgs,
  ...
}: {
  programs.walker = {
    package = pkgs.walker;
    enable = hostname == "b660" || hostname == "7540u";
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
