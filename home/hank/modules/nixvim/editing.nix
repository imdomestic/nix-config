# Shared editing behavior for terminal Neovim and the VS Code embedded instance.
{lib, ...}: let
  mkRaw = lib.nixvim.mkRaw;
in {
  globals = {
    mapleader = " ";
    maplocalleader = "\\";
  };
  opts = {
    ignorecase = true;
    smartcase = true;
    timeoutlen = 300;
  };
  plugins = {
    mini = {
      enable = true;
      modules.surround = {};
    };
    flash = {
      enable = true;
      settings = {};
    };
    treesitter.enable = true;
    treesitter-textobjects = {
      enable = true;
      settings = {
        select = {
          lookahead = true;
          include_surrounding_whitespace = false;
        };
        move.set_jumps = true;
      };
    };
  };
  keymaps = [
    {
      mode = "n";
      key = "<Esc>";
      action = "<Cmd>nohlsearch<CR>";
      options.desc = "Clear search highlight";
    }
    {
      mode = "n";
      key = ";";
      action = ":";
      options.desc = "Command line";
    }
    {
      mode = ["n" "x" "o"];
      key = "s";
      action = mkRaw ''function() require("flash").jump() end'';
      options.desc = "Flash";
    }
    {
      mode = ["n" "x" "o"];
      key = "S";
      action = mkRaw ''function() require("flash").treesitter() end'';
      options.desc = "Flash Treesitter";
    }
    {
      mode = ["o"];
      key = "r";
      action = mkRaw ''function() require("flash").remote() end'';
      options.desc = "Remote Flash";
    }
    {
      mode = ["o" "x"];
      key = "R";
      action = mkRaw ''function() require("flash").treesitter_search() end'';
      options.desc = "Treesitter Search";
    }
    {
      mode = ["c"];
      key = "<C-s>";
      action = mkRaw ''function() require("flash").toggle() end'';
      options.desc = "Toggle Flash Search";
    }
    # treesitter-textobjects 的 select/move 绑定。它们必须待在这个顶层
    # keymaps 列表里,不能挂在 plugins.treesitter-textobjects 旁边 ——
    # 见 docs/incidents.md#nixvim-plugins-keymaps-dropped。
    # select
    {
      mode = ["x" "o"];
      key = "af";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.select")
            .select_textobject("@function.outer", "textobjects")
        end
      '';
      options.desc = "Around function";
    }
    {
      mode = ["x" "o"];
      key = "if";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.select")
            .select_textobject("@function.inner", "textobjects")
        end
      '';
      options.desc = "Inside function";
    }
    {
      mode = ["x" "o"];
      key = "ac";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.select")
            .select_textobject("@class.outer", "textobjects")
        end
      '';
      options.desc = "Around class";
    }
    {
      mode = ["x" "o"];
      key = "ic";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.select")
            .select_textobject("@class.inner", "textobjects")
        end
      '';
      options.desc = "Inside class";
    }

    # move
    {
      mode = ["n" "x" "o"];
      key = "]m";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.move")
            .goto_next_start("@function.outer", "textobjects")
        end
      '';
      options.desc = "Next function start";
    }
    {
      mode = ["n" "x" "o"];
      key = "[m";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.move")
            .goto_previous_start("@function.outer", "textobjects")
        end
      '';
      options.desc = "Previous function start";
    }
    {
      mode = ["n" "x" "o"];
      key = "]]";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.move")
            .goto_next_start("@class.outer", "textobjects")
        end
      '';
      options.desc = "Next class start";
    }
    {
      mode = ["n" "x" "o"];
      key = "[[";
      action = mkRaw ''
        function()
          require("nvim-treesitter-textobjects.move")
            .goto_previous_start("@class.outer", "textobjects")
        end
      '';
      options.desc = "Previous class start";
    }
  ];
}
