{
  config,
  lib,
  pkgs,
  ...
}: let
  c = (import ../palettes/flat-white.nix).colors;
  selected = {
    fg = c.selection_fg;
    bg = c.selection_bg;
  };
  border = {fg = c.color4;};
in {
  programs.yazi = lib.mkIf config.programs.yazi.enable {
    # 共享 profile 原先把 flavor 写进了 yazi.toml；实际主题入口是 theme.toml。
    settings.theme = lib.mkForce {};
    theme = {
      flavor = {
        dark = "";
        light = "";
      };
      app.overall = {
        fg = c.foreground;
        bg = c.background;
      };
      mgr = {
        cwd.fg = c.color6;
        find_keyword = {
          fg = c.color3;
          bold = true;
        };
        find_position.fg = c.color5;
        marker_copied = {
          fg = c.color2;
          bg = c.color2;
        };
        marker_cut = {
          fg = c.color1;
          bg = c.color1;
        };
        marker_marked = {
          fg = c.color5;
          bg = c.color5;
        };
        marker_selected = {
          fg = c.color3;
          bg = c.color3;
        };
        count_copied = {
          fg = c.background;
          bg = c.color2;
        };
        count_cut = {
          fg = c.background;
          bg = c.color1;
        };
        count_selected = {
          fg = c.background;
          bg = c.color3;
        };
        border_style.fg = c.color8;
        syntect_theme = toString (import ../palettes/flat-white-tmtheme.nix {inherit pkgs;});
      };
      tabs = {
        active = {
          fg = c.background;
          bg = c.color4;
          bold = true;
        };
        inactive = {
          fg = c.color8;
          bg = c.color0;
        };
      };
      mode = {
        normal_main = {
          fg = c.background;
          bg = c.color4;
        };
        normal_alt = {
          fg = c.color4;
          bg = c.color0;
        };
        select_main = {
          fg = c.background;
          bg = c.color5;
        };
        select_alt = {
          fg = c.color5;
          bg = c.color0;
        };
        unset_main = {
          fg = c.background;
          bg = c.color3;
        };
        unset_alt = {
          fg = c.color3;
          bg = c.color0;
        };
      };
      indicator = {
        parent = selected;
        current = selected;
        preview = selected;
      };
      status = {
        overall = {
          fg = c.foreground;
          bg = c.color0;
        };
        perm_type.fg = c.color2;
        perm_read.fg = c.color3;
        perm_write.fg = c.color1;
        perm_exec.fg = c.color6;
        perm_sep.fg = c.color8;
        progress_label.fg = c.foreground;
        progress_normal = {
          fg = c.color2;
          bg = c.color0;
        };
        progress_error = {
          fg = c.color1;
          bg = c.color0;
        };
      };
      pick = {
        inherit border;
        active = selected;
        inactive.fg = c.foreground;
      };
      input = {
        inherit border selected;
        title.fg = c.color4;
        value.fg = c.foreground;
      };
      cmp = {
        inherit border;
        active = selected;
        inactive.fg = c.foreground;
      };
      tasks = {
        inherit border;
        title.fg = c.color4;
        hovered = selected;
      };
      which = {
        inherit border;
        mask.bg = c.color0;
        cand.fg = c.color6;
        rest.fg = c.color8;
        desc.fg = c.foreground;
        separator_style.fg = c.color8;
      };
      confirm = {
        inherit border;
        title.fg = c.color4;
        btn_yes = selected;
        btn_no.fg = c.foreground;
      };
      spot = {
        inherit border;
        title.fg = c.color4;
        tbl_col.fg = c.color6;
        tbl_cell = selected;
      };
      help = {
        on.fg = c.color6;
        run.fg = c.color5;
        desc.fg = c.foreground;
        hovered = selected;
        footer = {
          fg = c.background;
          bg = c.foreground;
        };
      };
      notify = {
        title_info.fg = c.color2;
        title_warn.fg = c.color3;
        title_error.fg = c.color1;
      };
      filetype.rules = [
        {
          mime = "image/*";
          fg = c.color3;
        }
        {
          mime = "{audio,video}/*";
          fg = c.color5;
        }
        {
          mime = "application/{zip,rar,7z*,tar,gzip,xz,zstd}";
          fg = c.color1;
        }
        {
          url = "*";
          is = "orphan";
          fg = c.color1;
        }
        {
          url = "*";
          is = "exec";
          fg = c.color2;
        }
        {
          url = "*/";
          fg = c.color4;
        }
        {
          url = "*";
          fg = c.foreground;
        }
      ];
    };
  };
}
