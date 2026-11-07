# Shared editing behavior for terminal Neovim and the VS Code embedded instance.
{
  lib,
  pkgs,
  ...
}: let
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
    treesitter = {
      enable = true;
      # nixvim 的默认是全部 ~330 个 grammar(约 255 MiB),这里只留真在写的语言。
      # VS Code 那份 nixvim 也吃这份列表;不在这里收窄的话,终端那边删掉的
      # grammar 还会被它留在 store 里。非 dev 的终端 nvim 在 default.nix 里再收窄。
      # 没有的:jsonc(json 兼管)、lean(lean.nvim 走 LSP 语义高亮)。
      grammarPackages = lib.mkDefault (with pkgs.vimPlugins.nvim-treesitter.builtGrammars; [
        # nvim 自身和插件(noice / markview)要的
        c
        lua
        luadoc
        luap
        markdown
        markdown_inline
        printf
        query
        regex
        vim
        vimdoc

        # 配置、数据、git
        diff
        dockerfile
        git_config
        git_rebase
        gitattributes
        gitcommit
        gitignore
        ini
        json
        json5
        just
        nix
        toml
        xml
        yaml

        # 语言
        agda
        bash
        cmake
        cpp
        css
        elm
        glsl
        go
        haskell
        html
        java
        javascript
        latex
        make
        nu
        ocaml
        python
        rust
        scss
        sql
        swift
        tsx
        typescript
        typst
      ]);
    };
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
