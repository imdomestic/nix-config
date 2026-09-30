{
  config,
  inputs,
  lib,
  ...
}: {
  imports = [inputs.zen-browser.homeModules.beta];

  programs.zen-browser = {
    enable = lib.mkDefault true;
    env.MOZ_ENABLE_WAYLAND = "1";
    profiles.default.isDefault = true;
  };

  xdg.mimeApps = lib.mkIf config.programs.zen-browser.enable {
    enable = true;
    defaultApplications = lib.genAttrs [
      "text/html"
      "application/xhtml+xml"
      "x-scheme-handler/http"
      "x-scheme-handler/https"
    ] (_: ["zen-beta.desktop"]);
  };
  home.sessionVariables = lib.mkIf config.programs.zen-browser.enable {
    BROWSER = lib.getExe config.programs.zen-browser.package;
  };
}
