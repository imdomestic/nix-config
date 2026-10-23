{
  config,
  lib,
  ...
}: let
  c = (import ./palette.nix).colors;
in {
  programs.btop = lib.mkIf config.programs.btop.enable {
    settings.color_theme = "flat-white";
    themes.flat-white = lib.concatStringsSep "\n" (lib.mapAttrsToList (name: color: ''theme[${name}]="${color}"'') {
      main_bg = c.background;
      main_fg = c.foreground;
      title = c.foreground;
      hi_fg = c.color4;
      selected_bg = c.selection_bg;
      selected_fg = c.selection_fg;
      inactive_fg = c.color8;
      graph_text = c.foreground;
      meter_bg = c.selection_bg;
      proc_misc = c.color6;
      cpu_box = c.color4;
      mem_box = c.color2;
      net_box = c.color5;
      proc_box = c.color6;
      div_line = c.color8;
      temp_start = c.color2;
      temp_mid = c.color3;
      temp_end = c.color1;
      cpu_start = c.color4;
      cpu_mid = c.color6;
      cpu_end = c.color2;
      free_start = c.color2;
      free_mid = c.color10;
      free_end = c.color10;
      cached_start = c.color5;
      cached_mid = c.color13;
      cached_end = c.color13;
      available_start = c.color6;
      available_mid = c.color14;
      available_end = c.color14;
      used_start = c.color3;
      used_mid = c.color11;
      used_end = c.color1;
      download_start = c.color4;
      download_mid = c.color12;
      download_end = c.color14;
      upload_start = c.color5;
      upload_mid = c.color13;
      upload_end = c.color9;
      process_start = c.color2;
      process_mid = c.color6;
      process_end = c.color4;
    });
  };
}
