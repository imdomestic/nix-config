{
  config,
  inputs,
  lib,
  ...
}: {
  imports = [inputs.zen-browser.homeModules.beta];

  programs.zen-browser = {
    enable = true;
    env.MOZ_ENABLE_WAYLAND = "1";
    profiles.default.isDefault = true;
  };

  xdg.mimeApps = {
    enable = true;
    defaultApplications = lib.genAttrs [
      "text/html"
      "application/xhtml+xml"
      "x-scheme-handler/http"
      "x-scheme-handler/https"
    ] (_: ["zen-beta.desktop"]);
  };
  home.sessionVariables.BROWSER = lib.getExe config.programs.zen-browser.package;
}
