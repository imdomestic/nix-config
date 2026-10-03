# linwhite = hank/default.nix 那套 + 输入法自动切换(macOS)。
{
  lib,
  pkgs,
  pkgs-unstable,
  ...
}: {
  imports = [./hank/default.nix];

  programs.nixvim = {
    extraPlugins = lib.optionals pkgs.stdenv.isDarwin [
      pkgs-unstable.vimPlugins.im-select-nvim
    ];

    extraConfigLua = lib.optionalString pkgs.stdenv.isDarwin ''
      require("im_select").setup({
        default_im_select = "com.apple.keylayout.ABC",
        default_command = "im-select",

        set_default_events = {
          "VimEnter",
          "FocusGained",
          "InsertLeave",
          "CmdlineLeave",
        },

        set_previous_events = {
          "InsertEnter",
        },

        keep_quiet_on_no_binary = false,
        async_switch_im = true,
       })
    '';
  };
}
