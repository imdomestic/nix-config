{
  inputs,
  lib,
  pkgs,
  ...
}: let
  zen = pkgs.writeShellScriptBin "zen" ''
    exec ${lib.getExe pkgs.flatpak} run app.zen_browser.zen "$@"
  '';
in {
  imports = [inputs.nix-flatpak.homeManagerModules.nix-flatpak];

  programs.zen-browser.enable = false;
  home.packages = [zen];
  home.sessionVariables.BROWSER = lib.getExe zen;
  xdg.mimeApps = {
    enable = true;
    defaultApplications = lib.genAttrs [
      "text/html"
      "application/xhtml+xml"
      "x-scheme-handler/http"
      "x-scheme-handler/https"
    ] (_: ["app.zen_browser.zen.desktop"]);
  };

  services.flatpak = {
    enable = true;
    packages = [
      "com.qq.QQ"
      "com.tencent.WeChat"
      "com.spotify.Client"
      "app.zen_browser.zen"
    ];
    update = {
      onActivation = true;
      auto = {
        enable = true;
        onCalendar = "daily";
      };
    };

    overrides = {
      "app.zen_browser.zen".Environment.MOZ_ENABLE_WAYLAND = "1";

      # WeChat's manifest only exposes X11; prefer Wayland with Qt's X11 fallback.
      "com.tencent.WeChat" = {
        Context.sockets = ["wayland"];
        Environment.QT_QPA_PLATFORM = "wayland;xcb";
      };
    };
  };
}
