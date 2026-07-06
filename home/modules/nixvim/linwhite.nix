# linwhite = shared base + input-method auto switching (macOS).
{pkgs-unstable, ...}: {
  imports = [./default.nix];

  programs.nixvim = {
    extraPlugins = [
      pkgs-unstable.vimPlugins.im-select-nvim
    ];

    extraConfigLua = ''
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
