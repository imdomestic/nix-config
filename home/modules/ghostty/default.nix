{
  config,
  pkgs,
  ...
}: let
  isLinux = pkgs.stdenv.isLinux;
  isHome = config.my.host.name == "aarch64-headless" || config.my.host.name == "x86_64-headless";

  # package = null 的意思是"配置文件照常下发,但别装 ghostty 本体":
  #   - darwin 上它由 homebrew 装
  #   - aarch64-headless / x86_64-headless 是纯 home-manager 的机器,
  #     那边终端是别人的事
  ghosttyPackage =
    if isHome || !isLinux
    then null
    else pkgs.ghostty;
in {
  programs.ghostty = {
    enable = true;
    package = ghosttyPackage;

    # **必须跟着 package 走。** 上游这个选项默认是 `stdenv.hostPlatform.isLinux`,
    # 而它自己又断言了 "systemd.enable cannot be true when package is null" ——
    # 于是 package = null 的 **Linux** home(就是上面两台 headless)会在求值期
    # 直接抛断言,`nix flake check` 整个红掉。
    #
    # 实测:2026-08-12 之前 `nix flake check` 就一直是 exit 1,失败的是
    # homeConfigurations."hosts/x86_64-headless/hank"。darwin 那几台没事,
    # 因为它们的默认值本来就是 false。
    systemd.enable = ghosttyPackage != null;

    enableZshIntegration = true;
    # installBatSyntax = false;
    themes = {
      kanso = {
        background = "#090E13";
        foreground = "#c5c9c7";
        cursor-color = "#c5c9c7";
        palette = [
          "0=#090E13"
          "1=#c4746e"
          "2=#8a9a7b"
          "3=#c4b28a"
          "4=#8ba4b0"
          "5=#a292a3"
          "6=#8ea4a2"
          "7=#a4a7a4"
          "8=#5C6066"
          "9=#e46876"
          "10=#87a987"
          "11=#e6c384"
          "12=#7fb4ca"
          "13=#938aa9"
          "14=#7aa89f"
          "15=#c5c9c7"
        ];
        selection-background = "#22262D";
        selection-foreground = "#c5c9c7";
      };
    };
    settings = {
      theme = "kanso";
      font-size =
        if isLinux
        then 11.5
        else 15;
      window-decoration = true;
      font-family =
        if isLinux
        then "Recursive"
        # Recursive/Nerd Font has no CJK glyphs; without an explicit fallback
        # Ghostty's own font matching lands on a Song/Kai-style face instead
        # of the system cascade (PingFang SC). Order matters: first hit wins.
        else [
          "RecMonoSmCasual Nerd Font Mono"
          "PingFang SC"
        ];
      background-opacity = 0.85;
      background-blur-radius = 20;
      macos-option-as-alt = true;
      macos-titlebar-style = "tabs";
      shell-integration = "detect";
      auto-update = "off";
      cursor-style = "bar";
      cursor-style-blink = false;
      adjust-cursor-thickness = "250%";
      shell-integration-features = "no-cursor";
      clipboard-read = "allow";
      clipboard-write = "allow";
      cursor-click-to-move = true;
      term = "xterm-256color";
      font-thicken = true;
      keybind = [
        "alt+i=toggle_quick_terminal"
      ];
      macos-icon = "xray";
    };
  };
}
##==default_keybindings (Darwin has Super instead of C):
# reset font              C-0
# smaller/bigger font     C-'-/+'
# write_scrollback_file   C-j
# new_window/close_surface/quit/close_window   C-S-n/w/q/ A-f4
# new_tab                 C-S-t
# split_right/down        C-S-o/e
# gotosplit left/right    S-Sup-</>
# goto split left/down/up/right <-..
# scroll top/bottom       S-home/end
# scroll up/down          S-pageup/pagedown
# semantic prompts?       S-C-pageup/pagedown
# inspector               S-C-i
# toggle fullscreen       C-Enter
# goto tab [1-9]          C-[1-9]

