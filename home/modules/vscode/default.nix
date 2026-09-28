{
  inputs,
  pkgs,
  lib,
  config,
  ...
}: let
  neovim = inputs.nixvim.legacyPackages.${pkgs.stdenv.hostPlatform.system}.makeNixvimWithModule {
    inherit pkgs;
    module = ../nixvim/hank/vscode.nix;
  };
  defaultsExtension = pkgs.callPackage ./defaults-extension.nix {inherit neovim;};
in {
  options.my.vscode.enable = lib.mkEnableOption "VS Code with shared Nixvim editing and GUI-overridable defaults";

  config = lib.mkIf config.my.vscode.enable {
    programs.vscode = {
      enable = true;
      # A CLI-only package lets HM refresh its extension index without another app.
      package = lib.mkIf pkgs.stdenv.hostPlatform.isDarwin (pkgs.writeShellScriptBin "code" ''
        exec "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" "$@"
      '');
      mutableExtensionsDir = true;
      profiles.default.extensions = [
        pkgs.vscode-extensions.asvetliakov.vscode-neovim
        defaultsExtension
      ];
      # Leave userSettings/keybindings empty; see docs/decisions.md#vscode-user-overrides.
    };
  };
}
