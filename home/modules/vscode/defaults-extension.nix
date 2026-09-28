{
  lib,
  stdenv,
  vscode-utils,
  writeText,
  neovim,
  editorFont,
}: let
  platform =
    if stdenv.hostPlatform.isDarwin
    then "darwin"
    else "linux";
  navigation = [
    {
      key = "ctrl+h";
      command = "workbench.action.navigateLeft";
    }
    {
      key = "ctrl+j";
      command = "workbench.action.navigateDown";
    }
    {
      key = "ctrl+k";
      command = "workbench.action.navigateUp";
    }
    {
      key = "ctrl+l";
      command = "workbench.action.navigateRight";
    }
  ];
  manifest = {
    name = "nixvim-defaults";
    publisher = "hank";
    version = "1.0.0";
    displayName = "Hank's Nixvim Defaults";
    description = "Nix-managed defaults; override settings and shortcuts normally in the VS Code GUI.";
    engines.vscode = "^1.96.0";
    categories = ["Keymaps" "Snippets"];
    extensionKind = ["ui"];
    extensionDependencies = ["asvetliakov.vscode-neovim"];
    contributes = {
      configurationDefaults = {
        "vscode-neovim.neovimExecutablePaths.${platform}" = "${neovim}/bin/nvim";
        "editor.fontFamily" = editorFont.family;
        "editor.fontSize" = editorFont.size;
        "editor.lineNumbers" = "on";
        "editor.cursorSurroundingLines" = 10;
        "editor.renderLineHighlight" = "line";
        "editor.inlayHints.enabled" = "off";
      };
      keybindings =
        map (binding:
          binding
          // {
            when = "neovim.init && !editorTextFocus && !inQuickOpen && (!inputFocus || terminalFocus)";
          })
        navigation
        ++ [
          {
            key = "ctrl+j";
            command = "workbench.action.quickOpenSelectNext";
            when = "inQuickOpen && neovim.mode != cmdline";
          }
          {
            key = "ctrl+k";
            command = "workbench.action.quickOpenSelectPrevious";
            when = "inQuickOpen && neovim.mode != cmdline";
          }
          {
            key = "alt+m";
            command = "workbench.action.terminal.toggleTerminal";
            when = "terminalFocus";
          }
        ];
      snippets = [
        {
          language = "rust";
          path = "./snippets/rust.json";
        }
      ];
    };
  };
in
  vscode-utils.buildVscodeExtension {
    pname = "hank-nixvim-defaults";
    inherit (manifest) version;
    vscodeExtPublisher = manifest.publisher;
    vscodeExtName = manifest.name;
    vscodeExtUniqueId = "${manifest.publisher}.${manifest.name}";
    dontUnpack = true;
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/$installPrefix/snippets"
      cp ${writeText "nixvim-defaults-package.json" (builtins.toJSON manifest)} "$out/$installPrefix/package.json"
      cp ${../nixvim/hank/snippets/rust.json} "$out/$installPrefix/snippets/rust.json"
      runHook postInstall
    '';
    passthru = {inherit neovim manifest;};
    meta.license = lib.licenses.mit;
  }
