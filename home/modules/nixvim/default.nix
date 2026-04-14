{
  inputs,
  pkgs,
  pkgs-unstable,
  ...
}: let
  mkRaw = inputs.nixvim.raw;
in {
  programs.nixvim = {
    enable = true;
    enableMan = true;
    nixpkgs.pkgs = pkgs-unstable;
    package = pkgs-unstable.neovim-unwrapped;

    extraPlugins = [
      pkgs-unstable.vimPlugins."evergarden-nvim"
    ];

    extraPackages = [
      pkgs.lazygit
    ];

    extraFiles = {
      "snippets/package.json".source = ./nvim-snippets/package.json;
      "snippets/rust.json".source = ./nvim-snippets/rust.json;
    };

    globals = {
      mapleader = " ";
      maplocalleader = "\\";
      clipboard = {
        name = "OSC 52";
        copy = {
          "+" = mkRaw ''require("vim.ui.clipboard.osc52").copy("+")'';
          "*" = mkRaw ''require("vim.ui.clipboard.osc52").copy("*")'';
        };
        paste = {
          "+" = mkRaw ''require("vim.ui.clipboard.osc52").paste("+")'';
          "*" = mkRaw ''require("vim.ui.clipboard.osc52").paste("*")'';
        };
      };
    };

    opts = {
      number = true;
      mouse = "a";
      showmode = false;
      breakindent = true;
      undofile = true;
      ignorecase = true;
      smartcase = true;
      signcolumn = "yes:1";
      updatetime = 125;
      timeoutlen = 300;
      splitright = true;
      splitbelow = true;
      inccommand = "split";
      cursorline = true;
      scrolloff = 10;
      laststatus = 3;
      foldenable = true;
      foldlevel = 99;
      foldlevelstart = 99;
      cmdheight = 0;
      fillchars = {
        eob = " ";
      };
    };

    filetype.extension = {
      templ = "templ";
    };

    diagnostic.settings = {
      virtual_lines = false;
      virtual_text = true;
      update_in_insert = true;
      severity_sort = true;
      float = {
        border = "rounded";
        source = "if_many";
      };
      underline.severity = mkRaw "vim.diagnostic.severity.ERROR";
      signs = {
        numhl.__raw = ''
          {
            [vim.diagnostic.severity.ERROR] = "DiagnosticError",
            [vim.diagnostic.severity.WARN] = "DiagnosticWarn",
            [vim.diagnostic.severity.INFO] = "DiagnosticInfo",
            [vim.diagnostic.severity.HINT] = "DiagnosticHint",
          }
        '';
        text.__raw = ''
          {
            [vim.diagnostic.severity.ERROR] = "",
            [vim.diagnostic.severity.WARN] = "",
            [vim.diagnostic.severity.INFO] = "",
            [vim.diagnostic.severity.HINT] = "",
          }
        '';
      };
    };

    autoGroups = {
      highlight-yank.clear = true;
      terminal-cleanup.clear = true;
      indent-two.clear = true;
      indent-rust.clear = true;
      haskell-extra.clear = true;
      rust-extra.clear = true;
    };

    autoCmd = [
      {
        event = "TextYankPost";
        group = "highlight-yank";
        desc = "Highlight when yanking (copying) text";
        callback = mkRaw ''
          function()
            vim.highlight.on_yank()
          end
        '';
      }
      {
        event = "VimLeavePre";
        callback = mkRaw ''
          function()
            if vim.uv.guess_handle(vim.v.stderr) ~= "tty" then
              return
            end

            vim.api.nvim_chan_send(vim.v.stderr, "\x1b[6 q")
          end
        '';
      }
      {
        event = "VimLeavePre";
        group = "terminal-cleanup";
        desc = "Exit: Kill all background terminals automatically";
        callback = mkRaw ''
          function()
            for _, buf in ipairs(vim.api.nvim_list_bufs()) do
              if vim.api.nvim_buf_is_valid(buf) and vim.bo[buf].buftype == "terminal" then
                vim.api.nvim_buf_delete(buf, { force = true })
              end
            end
          end
        '';
      }
      {
        event = "FileType";
        group = "indent-two";
        pattern = [
          "bs"
          "c"
          "cabal"
          "cmake"
          "cpp"
          "haskell"
          "java"
          "json"
          "lua"
          "nix"
          "yaml"
        ];
        callback = mkRaw ''
          function()
            vim.bo.expandtab = true
            vim.bo.tabstop = 2
            vim.bo.softtabstop = 2
            vim.bo.shiftwidth = 2
          end
        '';
      }
      {
        event = "FileType";
        group = "indent-rust";
        pattern = "rust";
        callback = mkRaw ''
          function()
            vim.bo.expandtab = true
            vim.bo.tabstop = 4
            vim.bo.softtabstop = 4
            vim.bo.shiftwidth = 4
          end
        '';
      }
      {
        event = "FileType";
        group = "haskell-extra";
        pattern = "haskell";
        callback = mkRaw ''
          function(args)
            local ht = require("haskell-tools")
            local opts = { noremap = true, silent = true, buffer = args.buf }

            vim.keymap.set("n", "<space>ll", vim.lsp.codelens.run, opts)
            vim.keymap.set("n", "<space>le", ht.lsp.buf_eval_all, opts)
          end
        '';
      }
      {
        event = "FileType";
        group = "rust-extra";
        pattern = "rust";
        callback = mkRaw ''
          function(args)
            vim.keymap.set("n", "<leader>a", function()
              vim.cmd.RustLsp("codeAction")
            end, { silent = true, buffer = args.buf })
          end
        '';
      }
    ];

    keymaps = [
      {
        mode = "n";
        key = "<Esc>";
        action = "<Cmd>nohlsearch<CR>";
      }
      {
        mode = "n";
        key = "[b";
        action = "<Cmd>bprev<CR>";
      }
      {
        mode = "n";
        key = "]b";
        action = "<Cmd>bnext<CR>";
      }
      {
        mode = "n";
        key = "<leader>c";
        action = mkRaw ''
          function()
            require("snacks").bufdelete()
          end
        '';
        options.desc = "Delete buffer";
      }
      {
        mode = "n";
        key = "<leader>/";
        action = "gcc";
        options = {
          remap = true;
          desc = "Toggle comment line";
        };
      }
      {
        mode = "v";
        key = "<leader>/";
        action = "gc";
        options = {
          remap = true;
          desc = "Toggle comment";
        };
      }
      {
        mode = "n";
        key = "<leader>q";
        action = "<Cmd>q<CR>";
      }
      {
        mode = "n";
        key = "<leader>Q";
        action = "<Cmd>qa!<CR>";
      }
      {
        mode = "v";
        key = "J";
        action = "5j";
      }
      {
        mode = "n";
        key = "<leader>w";
        action = "<Cmd>w<CR>";
      }
      {
        mode = "n";
        key = "j";
        action = "gj";
      }
      {
        mode = "n";
        key = "k";
        action = "gk";
      }
      {
        mode = "x";
        key = "j";
        action = "gj";
      }
      {
        mode = "x";
        key = "k";
        action = "gk";
      }
      {
        mode = "n";
        key = ";";
        action = ":";
      }
      {
        mode = "n";
        key = "<M-n>";
        action = mkRaw ''
          function()
            require("snacks").terminal()
          end
        '';
        options.desc = "Toggle terminal";
      }
      {
        mode = "t";
        key = "<M-n>";
        action = mkRaw ''
          function()
            require("snacks").terminal()
          end
        '';
        options.desc = "Toggle terminal";
      }
      {
        mode = "n";
        key = "<leader>th";
        action = mkRaw ''
          function()
            require("snacks").terminal()
          end
        '';
        options.desc = "Toggle terminal";
      }
      {
        mode = "t";
        key = "<Esc><Esc>";
        action = "<C-\\><C-n>";
        options.desc = "Exit terminal mode";
      }
      {
        mode = "n";
        key = "<C-h>";
        action = "<C-w><C-h>";
        options.desc = "Move focus to the left window";
      }
      {
        mode = "n";
        key = "<C-l>";
        action = "<C-w><C-l>";
        options.desc = "Move focus to the right window";
      }
      {
        mode = "n";
        key = "<C-j>";
        action = "<C-w><C-j>";
        options.desc = "Move focus to the lower window";
      }
      {
        mode = "n";
        key = "<C-k>";
        action = "<C-w><C-k>";
        options.desc = "Move focus to the upper window";
      }
      {
        mode = "n";
        key = "<leader>ui";
        action = mkRaw ''
          function()
            local ok, input = pcall(vim.fn.input, "Set indent value (>0 expandtab, <=0 noexpandtab): ")
            if not ok then
              return
            end

            local indent = tonumber(input)
            if not indent or indent == 0 then
              return
            end

            vim.bo.expandtab = indent > 0
            indent = math.abs(indent)
            vim.bo.tabstop = indent
            vim.bo.softtabstop = indent
            vim.bo.shiftwidth = indent
          end
        '';
      }
      {
        mode = "n";
        key = "<leader>f<space>";
        action = mkRaw ''
          function()
            require("snacks").picker.smart()
          end
        '';
        options.desc = "Smart find files";
      }
      {
        mode = "n";
        key = "<leader>fr";
        action = mkRaw ''
          function()
            require("snacks").picker.recent()
          end
        '';
        options.desc = "Recent files";
      }
      {
        mode = "n";
        key = "<leader>ff";
        action = mkRaw ''
          function()
            require("snacks").picker.files()
          end
        '';
        options.desc = "Find files";
      }
      {
        mode = "n";
        key = "<leader>fw";
        action = mkRaw ''
          function()
            require("snacks").picker.grep()
          end
        '';
        options.desc = "Grep files";
      }
      {
        mode = "n";
        key = "<leader>fi";
        action = mkRaw ''
          function()
            require("snacks").picker.icons()
          end
        '';
        options.desc = "Icons";
      }
      {
        mode = "n";
        key = "<leader>fk";
        action = mkRaw ''
          function()
            require("snacks").picker.keymaps()
          end
        '';
        options.desc = "Keymaps";
      }
      {
        mode = "n";
        key = "<leader>fu";
        action = mkRaw ''
          function()
            require("snacks").picker.undo()
          end
        '';
        options.desc = "Undo history";
      }
      {
        mode = "n";
        key = "<leader>fs";
        action = mkRaw ''
          function()
            require("snacks").picker.lsp_workspace_symbols()
          end
        '';
        options.desc = "LSP symbols";
      }
      {
        mode = "n";
        key = "<leader>g";
        action = mkRaw ''
          function()
            require("snacks").lazygit()
          end
        '';
        options.desc = "Lazygit";
      }
      {
        mode = "n";
        key = "<leader>e";
        action = mkRaw ''
          function()
            require("snacks").explorer()
          end
        '';
        options.desc = "Explorer";
      }
      {
        mode = "n";
        key = "<leader>lD";
        action = mkRaw ''
          function()
            require("snacks").picker.diagnostics()
          end
        '';
        options.desc = "Diagnostics";
      }
      {
        mode = [
          "n"
          "i"
        ];
        key = "<M-;>";
        action = mkRaw ''
          function()
            require("sidekick").nes_jump_or_apply()
          end
        '';
        options.desc = "Sidekick NES jump/apply";
      }
      {
        mode = "n";
        key = "<leader>aa";
        action = mkRaw ''
          function()
            require("sidekick.cli").toggle({ name = "codex", focus = true })
          end
        '';
        options.desc = "Sidekick Codex";
      }
      {
        mode = "n";
        key = "<leader>as";
        action = mkRaw ''
          function()
            require("sidekick.cli").select({ filter = { installed = true } })
          end
        '';
        options.desc = "Select Sidekick tool";
      }
    ];

    plugins = {
      lz-n.enable = true;

      snacks = {
        enable = true;
        settings = {
          dashboard.enabled = false;
          image.enabled = true;
          input.enabled = true;
          notifier.enabled = true;
          lazygit.enabled = true;
          words.enabled = true;
          indent = {
            enabled = true;
            animate.enabled = false;
          };
          picker = {
            enabled = true;
            ui_select = true;
            sources.explorer.layout.layout.width = 30;
          };
          terminal = {
            enabled = true;
            win = {
              height = 10;
              position = "bottom";
              style = "minimal";
            };
          };
          explorer = {
            enabled = true;
            replace_netrw = true;
          };
        };
      };

      noice = {
        enable = true;
        lazyLoad.settings.event = "DeferredUIEnter";
        settings = {
          lsp = {
            signature.enabled = false;
            hover.enabled = false;
          };
          cmdline = {
            enabled = true;
            view = "cmdline_popup";
          };
          routes = [
            {
              filter = {
                event = "msg_show";
                kind = "";
                find = "written";
              };
              opts.skip = true;
            }
          ];
          notify.enabled = false;
          presets = {
            bottom_search = true;
            command_palette = true;
            long_message_to_split = true;
            inc_rename = false;
            lsp_doc_border = false;
          };
        };
      };

      flash = {
        enable = true;
        lazyLoad.settings = {
          event = "DeferredUIEnter";
          keys = [
            (mkRaw ''{ "s", function() require("flash").jump() end, mode = { "n", "x", "o" }, desc = "Flash" }'')
            (mkRaw ''{ "S", function() require("flash").treesitter() end, mode = { "n", "x", "o" }, desc = "Flash Treesitter" }'')
            (mkRaw ''{ "r", function() require("flash").remote() end, mode = "o", desc = "Remote Flash" }'')
            (mkRaw ''{ "R", function() require("flash").treesitter_search() end, mode = { "o", "x" }, desc = "Treesitter Search" }'')
            (mkRaw ''{ "<C-s>", function() require("flash").toggle() end, mode = "c", desc = "Toggle Flash Search" }'')
          ];
        };
        settings = {};
      };

      smart-splits = {
        enable = true;
        lazyLoad.settings = {
          event = "DeferredUIEnter";
          keys = [
            (mkRaw ''{ "<C-Up>", function() require("smart-splits").resize_up() end, mode = { "n", "t" }, desc = "Resize split up" }'')
            (mkRaw ''{ "<C-Down>", function() require("smart-splits").resize_down() end, mode = { "n", "t" }, desc = "Resize split down" }'')
            (mkRaw ''{ "<C-Left>", function() require("smart-splits").resize_left() end, mode = { "n", "t" }, desc = "Resize split left" }'')
            (mkRaw ''{ "<C-Right>", function() require("smart-splits").resize_right() end, mode = { "n", "t" }, desc = "Resize split right" }'')
          ];
        };
        settings.ignored_filetypes = ["SnacksExplorer"];
      };

      persistence = {
        enable = true;
        lazyLoad.settings.event = "BufReadPre";
        settings = {};
      };

      mini = {
        enable = true;
        mockDevIcons = true;
        modules = {
          icons = {};
          tabline = {};
          pairs = {};
          surround = {};
          comment = {};
          statusline = {
            use_icons = true;
            content.active = mkRaw ''
              function()
                local mode, mode_hl = MiniStatusline.section_mode({ trunc_width = 120 })
                local git = MiniStatusline.section_git({ trunc_width = 40 })
                local diagnostics = MiniStatusline.section_diagnostics({ trunc_width = 75 })

                local function lsp_client()
                  local buf_clients = vim.lsp.get_clients({ bufnr = 0 })
                  if #buf_clients == 0 then
                    return ""
                  end

                  local names = {}
                  for _, client in pairs(buf_clients) do
                    table.insert(names, client.name)
                  end

                  return " " .. table.concat(names, ", ")
                end

                local function macro()
                  if package.loaded["noice"] and require("noice").api.status.mode.has() then
                    return require("noice").api.status.mode.get()
                  end

                  local recording_register = vim.fn.reg_recording()
                  if recording_register == "" then
                    return ""
                  end

                  return "⏺ @" .. recording_register
                end

                return MiniStatusline.combine_groups({
                  { hl = mode_hl, strings = { mode } },
                  { hl = "MiniStatuslineDevinfo", strings = { git } },
                  "%<",
                  { hl = "MiniStatuslineFilename", strings = { "%=" } },
                  { hl = "MiniStatuslineFilename", strings = { diagnostics } },
                  "%=",
                  { hl = "MiniStatuslineFileinfo", strings = { lsp_client() } },
                  { hl = mode_hl, strings = { macro() } },
                })
              end
            '';
          };
          clue = {
            triggers = [
              {
                mode = ["n" "x"];
                keys = "<Leader>";
              }
              {
                mode = "n";
                keys = "[";
              }
              {
                mode = "n";
                keys = "]";
              }
              {
                mode = "i";
                keys = "<C-x>";
              }
              {
                mode = ["n" "x"];
                keys = "g";
              }
              {
                mode = ["n" "x"];
                keys = "'";
              }
              {
                mode = ["n" "x"];
                keys = "`";
              }
              {
                mode = ["n" "x"];
                keys = "\"";
              }
              {
                mode = ["i" "c"];
                keys = "<C-r>";
              }
              {
                mode = "n";
                keys = "<C-w>";
              }
              {
                mode = ["n" "x"];
                keys = "z";
              }
            ];
            clues = [
              (mkRaw ''require("mini.clue").gen_clues.square_brackets()'')
              (mkRaw ''require("mini.clue").gen_clues.builtin_completion()'')
              (mkRaw ''require("mini.clue").gen_clues.g()'')
              (mkRaw ''require("mini.clue").gen_clues.marks()'')
              (mkRaw ''require("mini.clue").gen_clues.registers()'')
              (mkRaw ''require("mini.clue").gen_clues.windows()'')
              (mkRaw ''require("mini.clue").gen_clues.z()'')
            ];
          };
        };
      };

      treesitter = {
        enable = true;
        highlight.enable = true;
        indent.enable = true;
        folding.enable = true;
      };

      treesitter-textobjects = {
        enable = true;

        settings = {
          select = {
            lookahead = true;
            include_surrounding_whitespace = false;
          };

          move = {
            set_jumps = true;
          };
        };
      };

      keymaps = [
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
        }
      ];

      friendly-snippets.enable = true;

      blink-cmp = {
        enable = true;
        setupLspCapabilities = true;
        settings = {
          keymap = {
            "<C-Space>" = [
              "show"
              "show_documentation"
              "hide_documentation"
            ];
            "<Up>" = [
              "select_prev"
              "fallback"
            ];
            "<Down>" = [
              "select_next"
              "fallback"
            ];
            "<C-N>" = [
              "select_next"
              "show"
            ];
            "<C-P>" = [
              "select_prev"
              "show"
            ];
            "<C-J>" = [
              "select_next"
              "fallback"
            ];
            "<C-K>" = [
              "select_prev"
              "fallback"
            ];
            "<C-U>" = [
              "scroll_documentation_up"
              "fallback"
            ];
            "<C-D>" = [
              "scroll_documentation_down"
              "fallback"
            ];
            "<C-e>" = [
              "hide"
              "fallback"
            ];
            "<CR>" = [
              "accept"
              "fallback"
            ];
            "<Tab>" = [
              "select_next"
              (mkRaw ''
                function(cmp)
                  local line, col = unpack(vim.api.nvim_win_get_cursor(0))
                  local has_words_before = col ~= 0
                    and vim.api.nvim_buf_get_lines(0, line - 1, line, true)[1]:sub(col, col):match("%s") == nil

                  if has_words_before or vim.api.nvim_get_mode().mode == "c" then
                    return cmp.show()
                  end
                end
              '')
              "fallback"
            ];
            "<S-Tab>" = [
              "select_prev"
              (mkRaw ''
                function(cmp)
                  if vim.api.nvim_get_mode().mode == "c" then
                    return cmp.show()
                  end
                end
              '')
              "fallback"
            ];
            "<M-l>" = [
              "snippet_forward"
              "fallback"
            ];
            "<M-h>" = [
              "snippet_backward"
              "fallback"
            ];
          };
          completion = {
            list.selection = {
              preselect = false;
              auto_insert = true;
            };
            menu = {
              auto_show = mkRaw ''
                function(ctx)
                  return ctx.mode ~= "cmdline"
                end
              '';
              border = "rounded";
              winhighlight = "Normal:NormalFloat,FloatBorder:FloatBorder,CursorLine:PmenuSel,Search:None";
              draw.treesitter = ["lsp"];
            };
            accept.auto_brackets.enabled = true;
            documentation = {
              auto_show = true;
              auto_show_delay_ms = 0;
              window = {
                border = "rounded";
                winhighlight = "Normal:NormalFloat,FloatBorder:FloatBorder,CursorLine:PmenuSel,Search:None";
              };
            };
          };
          signature.window = {
            border = "rounded";
            winhighlight = "Normal:NormalFloat,FloatBorder:FloatBorder";
          };
          appearance = {
            use_nvim_cmp_as_default = true;
            nerd_font_variant = "mono";
          };
          sources.default = [
            "lsp"
            "path"
            "snippets"
            "buffer"
          ];
          fuzzy.implementation = "prefer_rust_with_warning";
        };
      };

      copilot-lua = {
        enable = true;
        settings = {
          panel.enabled = false;
          suggestion.enabled = false;
        };
      };

      sidekick = {
        enable = true;
        settings = {
          cli = {
            mux = {
              enabled = true;
              backend = "tmux";
            };
          };
        };
      };

      rustaceanvim = {
        enable = true;
        settings.server.default_settings."rust-analyzer" = {
          files = {
            watcher = "client";
            exclude = [
              ".git"
              "target"
              "node_modules"
              ".direnv"
              ".venv"
              "venv"
              "dist"
              "build"
              ".flatpak-builder"
            ];
          };
          cargo = {
            extraEnv = {
              CARGO_PROFILE_RUST_ANALYZER_INHERITS = "dev";
            };
            extraArgs = [
              "--profile"
              "rust-analyzer"
            ];
          };
          checkOnSave = true;
          check = {
            command = "clippy";
            allTargets = false;
            extraArgs = ["--no-deps"];
            allFeatures = true;
          };
          inlayHints = {
            expressionAdjustmentHints.enable = "always";
            implicitDrops.enable = "always";
            implicitSizedBoundHints.enable = true;
          };
        };
      };

      haskell-tools.enable = true;

      lean = {
        enable = true;
        lazyLoad.settings.ft = "lean";
        settings = {
          mappings = true;
          infoview.orientation = "vertical";
        };
      };

      gitsigns = {
        enable = true;
        lazyLoad.settings.event = "DeferredUIEnter";
        settings = {
          signs = {
            add.text = "┃";
            change.text = "┃";
            delete.text = "_";
            topdelete.text = "‾";
            changedelete.text = "~";
            untracked.text = "┆";
          };
          current_line_blame = true;
          on_attach = mkRaw ''
            function(bufnr)
              local gitsigns = require("gitsigns")

              local function map(mode, lhs, rhs, opts)
                opts = opts or {}
                opts.buffer = bufnr
                vim.keymap.set(mode, lhs, rhs, opts)
              end

              map("n", "]c", function()
                if vim.wo.diff then
                  vim.cmd.normal({ "]c", bang = true })
                else
                  gitsigns.nav_hunk("next")
                end
              end, { desc = "Jump to next git change" })

              map("n", "[c", function()
                if vim.wo.diff then
                  vim.cmd.normal({ "[c", bang = true })
                else
                  gitsigns.nav_hunk("prev")
                end
              end, { desc = "Jump to previous git change" })

              map("v", "<leader>hs", function()
                gitsigns.stage_hunk({ vim.fn.line("."), vim.fn.line("v") })
              end, { desc = "Stage git hunk" })

              map("v", "<leader>hr", function()
                gitsigns.reset_hunk({ vim.fn.line("."), vim.fn.line("v") })
              end, { desc = "Reset git hunk" })

              map("n", "<leader>hs", gitsigns.stage_hunk, { desc = "Git stage hunk" })
              map("n", "<leader>hr", gitsigns.reset_hunk, { desc = "Git reset hunk" })
              map("n", "<leader>hS", gitsigns.stage_buffer, { desc = "Git stage buffer" })
              map("n", "<leader>hu", gitsigns.undo_stage_hunk, { desc = "Git undo stage hunk" })
              map("n", "<leader>hR", gitsigns.reset_buffer, { desc = "Git reset buffer" })
              map("n", "<leader>hp", gitsigns.preview_hunk, { desc = "Git preview hunk" })
              map("n", "<leader>hb", gitsigns.blame_line, { desc = "Git blame line" })
              map("n", "<leader>hd", gitsigns.diffthis, { desc = "Git diff against index" })
              map("n", "<leader>hD", function()
                gitsigns.diffthis("@")
              end, { desc = "Git diff against last commit" })
              map("n", "<leader>tb", gitsigns.toggle_current_line_blame, { desc = "Toggle git blame line" })
              map("n", "<leader>tD", gitsigns.toggle_deleted, { desc = "Toggle git deleted" })
            end
          '';
        };
      };

      lint = {
        enable = true;
        lintersByFt = {
          swift = ["swiftlint"];
          python = ["ruff"];
          haskell = ["hlint"];
        };
        autoCmd = {
          event = [
            "BufEnter"
            "BufWritePost"
            "InsertLeave"
          ];
          callback = mkRaw ''
            function()
              require("lint").try_lint()
            end
          '';
        };
      };

      conform-nvim = {
        enable = true;
        autoInstall.enable = false;
        lazyLoad.settings = {
          event = "BufWritePre";
          cmd = ["ConformInfo"];
          keys = [
            (mkRaw ''{ "<leader>lf", function() require("conform").format({ async = true, lsp_format = "fallback" }) end, mode = "n", desc = "Format buffer" }'')
          ];
        };
        settings = {
          notify_on_error = true;
          format_on_save = null;
          formatters_by_ft = {
            swift = ["swiftformat"];
            typst = ["typstyle"];
            json = ["biome"];
            html = ["biome"];
            css = ["biome"];
            markdown = ["biome"];
            haskell = ["ormolu"];
            ocaml = ["ocamlformat"];
            python = ["ruff"];
            nix = ["alejandra"];
            elm = ["elm_format"];
          };
        };
      };

      typst-preview = {
        enable = true;
        lazyLoad.settings.ft = "typst";
        settings = {};
      };

      lsp = {
        enable = true;
        keymaps = {
          silent = true;
          lspBuf = {
            "gd" = "definition";
            "gD" = "declaration";
            "gr" = "references";
            "gi" = "implementation";
            "<leader>lr" = "rename";
            "<leader>la" = "code_action";
          };
          extra = [
            {
              key = "<leader>ld";
              action = mkRaw ''
                function()
                  vim.diagnostic.open_float()
                end
              '';
              options.desc = "LSP: Hover diagnostic";
            }
            {
              key = "gh";
              action = mkRaw ''
                function()
                  vim.lsp.buf.typehierarchy()
                end
              '';
              options.desc = "LSP: Goto type hierarchy";
            }
            {
              key = "K";
              action = mkRaw ''
                function()
                  vim.lsp.buf.hover({ border = "rounded" })
                end
              '';
              options.desc = "LSP: Hover";
            }
            {
              key = "<leader>lH";
              action = mkRaw ''
                function()
                  local bufnr = vim.api.nvim_get_current_buf()
                  local enabled = vim.lsp.inlay_hint.is_enabled({ bufnr = bufnr })
                  vim.lsp.inlay_hint.enable(not enabled, { bufnr = bufnr })
                end
              '';
              options.desc = "LSP: Toggle inlay hints";
            }
          ];
        };
        servers = {
          basedpyright = {
            enable = true;
            packageFallback = true;
            cmd = [
              "basedpyright-langserver"
              "--stdio"
            ];
            filetypes = ["python"];
            rootMarkers = [
              "pyproject.toml"
              "requirements.txt"
            ];
            settings = {
              basedpyright.analysis = {
                autoSearchPaths = true;
                diagnosticMode = "openFilesOnly";
                useLibraryCodeForTypes = true;
              };
            };
          };

          bashls = {
            enable = true;
            packageFallback = true;
            cmd = [
              "bash-language-server"
              "start"
            ];
            filetypes = [
              "bash"
              "sh"
            ];
            rootMarkers = [".git"];
            settings.bashIde.globPattern = mkRaw ''vim.env.GLOB_PATTERN or "*@(.sh|.inc|.bash|.command)"'';
            extraOptions.single_file_support = true;
          };

          clangd = {
            enable = true;
            packageFallback = true;
            cmd = [
              "clangd"
              "--background-index"
            ];
            filetypes = [
              "c"
              "cpp"
            ];
            rootMarkers = [
              ".clangd"
              "compile_commands.json"
            ];
            extraOptions.single_file_support = true;
          };

          cssls = {
            enable = true;
            packageFallback = true;
            filetypes = [
              "css"
              "scss"
              "less"
            ];
            rootMarkers = [
              "package.json"
              ".git"
            ];
            settings = {
              css.validate = true;
              scss.validate = true;
              less.validate = true;
            };
            extraOptions.init_options.provideFormatter = true;
          };

          elmls = {
            enable = true;
            packageFallback = true;
            filetypes = ["elm"];
            rootMarkers = ["elm.json"];
            extraOptions.init_options = {
              elmReviewDiagnostics = "off";
              skipInstallPackageConfirmation = false;
              disableElmLSDiagnostics = false;
              onlyUpdateDiagnosticsOnSave = false;
            };
          };

          html = {
            enable = true;
            packageFallback = true;
            filetypes = [
              "html"
              "templ"
            ];
            rootMarkers = [
              "package.json"
              ".git"
            ];
            extraOptions.init_options = {
              provideFormatter = true;
              embeddedLanguages = {
                css = true;
                javascript = true;
              };
              configurationSection = [
                "html"
                "css"
                "javascript"
              ];
            };
          };

          jsonls = {
            enable = true;
            packageFallback = true;
            filetypes = [
              "json"
              "jsonc"
            ];
            rootMarkers = [".git"];
            extraOptions.init_options.provideFormatter = true;
          };

          lua_ls = {
            enable = true;
            packageFallback = true;
            cmd = ["lua-language-server"];
            filetypes = ["lua"];
            rootMarkers = [".git"];
            settings = {
              runtime.version = "LuaJIT";
              workspace = {
                checkThirdParty = false;
                library = mkRaw ''vim.api.nvim_get_runtime_file("", true)'';
              };
            };
          };

          neocmake = {
            enable = true;
            packageFallback = true;
            cmd = [
              "neocmakelsp"
              "--stdio"
            ];
            filetypes = ["cmake"];
            rootMarkers = [
              ".git"
              "build"
              "cmake"
            ];
            extraOptions.single_file_support = true;
          };

          nil_ls = {
            enable = true;
            packageFallback = true;
            cmd = ["nil"];
            filetypes = ["nix"];
            rootMarkers = [
              ".git"
              "flake.nix"
              "flake.lock"
            ];
            extraOptions.single_file_support = true;
          };

          taplo = {
            enable = true;
            packageFallback = true;
            cmd = [
              "taplo"
              "lsp"
              "stdio"
            ];
            filetypes = ["toml"];
            rootMarkers = [
              ".taplo.toml"
              "taplo.toml"
              ".git"
            ];
          };

          tinymist = {
            enable = true;
            packageFallback = true;
            cmd = ["tinymist"];
            filetypes = ["typst"];
            rootMarkers = [".git"];
          };

          yamlls = {
            enable = true;
            packageFallback = true;
            cmd = [
              "yaml-language-server"
              "--stdio"
            ];
            filetypes = [
              "yaml"
              "yaml.docker-compose"
              "yaml.gitlab"
            ];
            rootMarkers = [".git"];
            settings.redhat.telemetry.enabled = false;
          };
        };
      };
    };

    extraConfigLuaPost = ''
      require("evergarden").setup({
        theme = {
          variant = "winter",
          accent = "green",
        },
        editor = {
          transparent_background = false,
        },
        style = {
          types = {},
          keyword = {},
          search = { "reverse", "bold" },
          incsearch = { "reverse", "bold" },
        },
      })
      vim.cmd.colorscheme("evergarden")
    '';
  };
}
