{
  inputs,
  pkgs,
  # pkgs-unstable,
  lib,
  config,
  ...
}: let
  mkRaw = inputs.nixvim.lib.nixvim.mkRaw;
  # Dev machines (importing home/users/<user>/dev.nix) get the full setup;
  # everything gated on `dev` below stays out of the closure elsewhere.
  dev = config.my.nixvim.dev.enable;
  toLua = inputs.nixvim.lib.nixvim.toLuaObject;
  # React 那几个插件共用的 filetype 列表。
  reactFiletypes = [
    "javascript"
    "javascriptreact"
    "typescript"
    "typescriptreact"
  ];

  # LSP 的唯一真相:下面的 lsp.servers 和 VimEnter 守卫的白名单都从这里派生,
  # 不再是两份要手工同步的列表。
  #
  # 一个都不由 nixvim 安装(lsp.servers.*.package = null)。要用的装在
  # home/profiles/dev.nix 里,项目 devshell 里的版本会盖掉它 —— nixvim 不往
  # PATH 里塞东西,PATH 的顺序自然就是 devshell > home profile。
  #
  # exe 是给守卫用的可执行文件名,省略表示从 vim.lsp.config[name].cmd[1] 推。
  # 上游把 cmd 写成 function 的(为了优先用项目 node_modules 里那份)推不出来,
  # 必须点名,否则守卫永远为假、声明了也不会启动。
  # config 直接就是 vim.lsp.config 的表,省略的字段用 nvim-lspconfig 的默认值。
  externalServers = {
    basedpyright.config = {
      cmd = ["basedpyright-langserver" "--stdio"];
      filetypes = ["python"];
      root_markers = ["pyproject.toml" "requirements.txt"];
      settings.basedpyright.analysis = {
        autoSearchPaths = true;
        diagnosticMode = "openFilesOnly";
        useLibraryCodeForTypes = true;
      };
    };

    bashls.config = {
      cmd = ["bash-language-server" "start"];
      filetypes = ["bash" "sh"];
      root_markers = [".git"];
      single_file_support = true;
      settings.bashIde.globPattern = mkRaw ''vim.env.GLOB_PATTERN or "*@(.sh|.inc|.bash|.command)"'';
    };

    clangd.config = {
      cmd = ["clangd" "--background-index"];
      filetypes = ["c" "cpp"];
      root_markers = [".clangd" "compile_commands.json"];
      single_file_support = true;
    };

    cssls.config = {
      filetypes = ["css" "scss" "less"];
      root_markers = ["package.json" ".git"];
      init_options.provideFormatter = true;
      settings = {
        css.validate = true;
        scss.validate = true;
        less.validate = true;
      };
    };

    elmls.config = {
      filetypes = ["elm"];
      root_markers = ["elm.json"];
      init_options = {
        elmReviewDiagnostics = "off";
        skipInstallPackageConfirmation = false;
        disableElmLSDiagnostics = false;
        onlyUpdateDiagnosticsOnSave = false;
      };
    };

    html.config = {
      # templ 不接 html-lsp:html-lsp 把 templ 当 HTML 解析,会刷一堆假诊断。
      # templ 现在没有 LSP(要接的话是 templ 包自带的 `templ lsp`,不是
      # cornelis —— cornelis 是 Agda 的)。
      filetypes = ["html"];
      root_markers = ["package.json" ".git"];
      init_options = {
        provideFormatter = true;
        embeddedLanguages = {
          css = true;
          javascript = true;
        };
        configurationSection = ["html" "css" "javascript"];
      };
    };

    # jdtls / lemminx 是 kenneth 用的(kenneth.nix 里配)。列在这里只为了让
    # 守卫认得它们 —— config 是空的,不会生成任何 vim.lsp.config 调用。
    jdtls = {};
    lemminx = {};

    jsonls.config = {
      filetypes = ["json" "jsonc"];
      root_markers = [".git"];
      init_options.provideFormatter = true;
    };

    lua_ls.config = {
      cmd = ["lua-language-server"];
      filetypes = ["lua"];
      root_markers = [".git"];
      # 这里的 settings 是原样透传给 vim.lsp.config 的,所以 Lua 这一层要自己写。
      # 旧的 plugins.lsp 模块会按 server 自动套(`settings = cfg: { Lua = cfg; }`),
      # 迁过来时漏掉这层的话 lua-language-server 根本读不到。
      settings.Lua = {
        runtime.version = "LuaJIT";
        workspace = {
          checkThirdParty = false;
          library = mkRaw ''vim.api.nvim_get_runtime_file("", true)'';
        };
      };
    };

    neocmake.config = {
      cmd = ["neocmakelsp" "--stdio"];
      filetypes = ["cmake"];
      root_markers = [".git" "build" "cmake"];
      single_file_support = true;
    };

    nil_ls.config = {
      cmd = ["nil"];
      filetypes = ["nix"];
      root_markers = [".git" "flake.nix" "flake.lock"];
      single_file_support = true;
    };

    # 不写 cmd:上游默认先找项目 node_modules/.bin 里的那份,版本跟着项目走。
    # 代价是 cmd 成了 function,守卫推不出可执行文件名,所以这里点名。
    # root_markers 同理不写:上游 root_dir 是个函数,会去找 tailwind.config.*
    # 或带 @import "tailwindcss" 的 CSS。
    tailwindcss = {
      exe = "tailwindcss-language-server";
      config.settings.tailwindCSS.classFunctions = ["cn" "clsx" "cva" "tw" "twMerge"];
    };

    taplo.config = {
      cmd = ["taplo" "lsp" "stdio"];
      filetypes = ["toml"];
      root_markers = [".taplo.toml" "taplo.toml" ".git"];
    };

    tinymist.config = {
      cmd = ["tinymist"];
      filetypes = ["typst"];
      root_markers = [".git"];
    };

    vtsls.config = {
      cmd = ["vtsls" "--stdio"];
      # 上游默认还挂 vue,仓库里已经不装 vue-language-server 了。
      filetypes = reactFiletypes;
      # root_markers 不写:上游 root_dir 是函数,会先认 lockfile 再退到
      # tsconfig/.git,monorepo 里比一串 marker 准。
      settings = {
        vtsls.experimental.completion.enableServerSideFuzzyMatch = true;
        typescript = {
          updateImportsOnFileMove.enabled = "always";
          suggest.completeFunctionCalls = true;
          # 默认全关,靠 <leader>lH 临时开。
          inlayHints = {
            parameterNames.enabled = "literals";
            parameterTypes.enabled = true;
            propertyDeclarationTypes.enabled = true;
            functionLikeReturnTypes.enabled = true;
            variableTypes.enabled = false;
          };
        };
      };
    };

    yamlls.config = {
      cmd = ["yaml-language-server" "--stdio"];
      filetypes = ["yaml" "yaml.docker-compose" "yaml.gitlab"];
      root_markers = [".git"];
      # 旧模块会把它套成 yaml.redhat.telemetry(错路径);顶层 redhat.telemetry
      # 才是 yaml-language-server 读的地方,现在原样透传正好对。
      settings.redhat.telemetry.enabled = false;
    };
  };
in {
  imports = [
    inputs.nixvim.homeModules.nixvim
    ./options.nix
  ];

  # nixvim replaces the plain neovim enabled by home/profiles/base.nix
  programs.neovim.enable = lib.mkForce false;

  programs.nixvim = {
    enable = true;
    enableMan = true;
    defaultEditor = true;
    # viAlias = true;
    # vimAlias = true;
    # nixpkgs.pkgs = pkgs-unstable;
    nixpkgs.pkgs = pkgs;
    # package = pkgs-unstable.neovim-unwrapped;
    package = pkgs.neovim-unwrapped;
    performance.byteCompileLua.enable = true;

    # Ruby provider pulls a full clang/llvm toolchain (~800 MiB) and is unused.
    withRuby = false;

    extraPlugins = [
      pkgs.vimPlugins."evergarden-nvim"
      # pkgs.vimPlugins.kanso-nvim
    ];

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
      # 外部 agent（Claude Code 等）在另一个 tmux window 里改仓库文件，
      # 切回来时未修改的 buffer 自动从磁盘重载。配合下面的 auto-reload 组。
      autoread = true;
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
      # nvim 默认 "ltToOCF" + "A"：发现残留 swap 时不再弹 E325 ATTENTION 提示。
      # 该提示在 snacks picker/explorer 的跳转里无法交互，会直接抛 Lua error。
      shortmess = "ltToOCFA";
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
        # 空字符串 = 不放 sign,但 numhl 照旧 —— signcolumn 只有一列
        # (opts.signcolumn = "yes:1"),诊断图标会把 gitsigns 的 hunk 标记顶掉。
        # 诊断只靠上面的 numhl 把行号染色。注意不能写成 text = {},那样 nvim
        # 会退回它自己的默认图标 "E "。
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
      auto-reload.clear = true;
      highlight-yank.clear = true;
      terminal-cleanup.clear = true;
      external-lsp.clear = true;
      lsp-document-color.clear = true;
      indent-two.clear = true;
      indent-four.clear = true;
      haskell-extra.clear = true;
      rust-extra.clear = true;
    };

    autoCmd =
      [
        {
          event = "VimEnter";
          group = "external-lsp";
          desc = "Enable configured language servers already available on PATH";
          callback = mkRaw ''
            function()
              -- true = 从 vim.lsp.config[server].cmd[1] 推可执行文件名。
              -- tailwindcss 这类上游把 cmd 写成 function(为了优先用项目
              -- node_modules/.bin 里的那份),推不出来,只能在这里点名 ——
              -- 写成 true 的话守卫永远为假,声明了也不会启动。
              local external_lsp_servers = ${toLua (lib.mapAttrs (_: srv: srv.exe or true) externalServers)}
              for server, executable in pairs(external_lsp_servers) do
                if executable == true then
                  local lsp_config = vim.lsp.config[server]
                  local cmd = type(lsp_config) == "table" and lsp_config.cmd or nil
                  executable = type(cmd) == "table" and cmd[1] or nil
                end
                if type(executable) == "string" and vim.fn.executable(executable) == 1 then
                  vim.lsp.enable(server)
                end
              end
            end
          '';
        }
        {
          event = "LspAttach";
          group = "lsp-document-color";
          desc = "Show LSP color swatches for tailwind class names";
          callback = mkRaw ''
            function(args)
              local client = vim.lsp.get_client_by_id(args.data.client_id)
              -- 只给 tailwindcss 开。cssls 也实现了 documentColor,在 css
              -- 文件里会和 highlight-colors 画重。
              if client and client.name == "tailwindcss" then
                vim.lsp.document_color.enable(
                  true,
                  { bufnr = args.buf, client_id = client.id },
                  { style = _G.__hank_lsp_color_swatch }
                )
              end
            end
          '';
        }
        {
          event = [
            "FocusGained"
            "BufEnter"
            "TermClose"
            "TermLeave"
          ];
          group = "auto-reload";
          desc = "Check for external file changes (autoread only triggers on checktime)";
          callback = mkRaw ''
            function()
              -- checktime 在 cmdline / cmdwin 里会抛 E11，nofile buffer 也无盘可查。
              if vim.bo.buftype ~= "nofile" and vim.fn.mode() ~= "c" and vim.fn.getcmdwintype() == "" then
                vim.cmd.checktime()
              end
            end
          '';
        }
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
            # java 不在这里:它归 indent-four(两边都列会让生效值取决于列表顺序)。
            "json"
            "lua"
            "nix"
            "lean"
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
          group = "indent-four";
          pattern = [
            "rust"
            "zig"
            "python"
            "php"
            "csharp"
            "kotlin"
            "java"
            "go"
          ];
          callback = mkRaw ''
            function()
              vim.bo.expandtab = true
              vim.bo.tabstop = 4
              vim.bo.softtabstop = 4
              vim.bo.shiftwidth = 4
            end
          '';
        }
      ]
      ++ lib.optionals dev [
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
        mode = ["n" "o"];
        key = "[b";
        action = "<Cmd>bprev<CR>";
      }
      {
        mode = ["n" "o"];
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
        # o 也要:operator-pending 序列(`3kj`)里同样是 gj/gk。
        # 带 count 时退回原生 j/k:`10j` 要的是 10 个缓冲区行,不是屏幕行。
        mode = ["n" "x" "o"];
        key = "j";
        action = "v:count == 0 ? 'gj' : 'j'";
        options.expr = true;
      }
      {
        mode = ["n" "x" "o"];
        key = "k";
        action = "v:count == 0 ? 'gk' : 'k'";
        options.expr = true;
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
        key = "<leader>fb";
        action = mkRaw ''
          function()
            require("snacks").picker.buffers()
          end
        '';
        options.desc = "Buffers";
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

    # Language servers come from the host/profile/devshell, never Nixvim.
    dependencies = {
      lean.enable = false;
      rust-analyzer.enable = false;
    };

    plugins = {
      lz-n.enable = true;

      # 新的 lsp.* 模块不再自带 nvim-lspconfig。我们要它:cssls/html/jsonls
      # 的默认 cmd、tailwindcss 那个会找 node_modules 的 cmd function、
      # vtsls 的 root_dir 函数,全靠它提供。
      lspconfig.enable = true;

      sleuth.enable = true;

      codesnap = {
        enable = dev;
        lazyLoad.settings.cmd = [
          "CodeSnap"
          "CodeSnapSave"
          "CodeSnapASCII"
          "CodeSnapHighlight"
          "CodeSnapSaveHighlight"
        ];
        settings = {
          has_breadcrumbs = false;
          has_line_number = true;
          mac_window_bar = true;
          save_path = "~/Downloads/";
        };
      };

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
          comment = lib.optionalAttrs dev {
            options.custom_commentstring = mkRaw ''
              function()
                -- ts-context-commentstring 按 ft 懒加载,tsx 之外 require
                -- 不到,退回 buffer 自己的 commentstring。
                local ok, ts_context = pcall(require, "ts_context_commentstring")
                if not ok then
                  return vim.bo.commentstring
                end
                return ts_context.calculate_commentstring() or vim.bo.commentstring
              end
            '';
          };
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
        # Non-dev machines only carry grammars for config editing; dev keeps
        # the nixvim default (all grammars).
        grammarPackages = lib.mkIf (!dev) (with pkgs.vimPlugins.nvim-treesitter.builtGrammars; [
          bash
          c
          cpp
          json
          lua
          markdown
          markdown_inline
          nix
          regex
          toml
          vim
          vimdoc
          yaml
        ]);
      };

      # 它的 af/if/ac/ic 和 ]m/[m/]]/[[ 绑定在上面那个顶层 keymaps 列表里。
      treesitter-textobjects = {
        enable = true;
        lazyLoad.settings.event = "DeferredUIEnter";

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

      # 前端(React + Tailwind)。LSP 在下面 plugins.lsp.servers 里统一声明,
      # 这里只管编辑体验,全部跟着 dev 走。
      ts-autotag = {
        enable = dev;
        lazyLoad.settings.ft = reactFiletypes ++ ["html" "xml" "markdown"];
      };

      ts-context-commentstring = {
        enable = dev;
        lazyLoad.settings.ft = reactFiletypes;
        # 由 mini.comment 的 custom_commentstring 钩子按需调用,
        # 不用它自己再挂一套 autocmd 改 commentstring。
        settings.enable_autocmd = false;
      };

      package-info = {
        enable = dev;
        lazyLoad.settings.ft = ["json"];
      };

      friendly-snippets.enable = true;

      blink-cmp = {
        enable = true;
        # 这个选项写的是 plugins.lsp.capabilities,而那条路只在 plugins.lsp.enable
        # 为真时才生成代码。迁到新模块之后它是空转的,capabilities 改由
        # lsp.servers."*".config 注入。
        setupLspCapabilities = false;
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
              draw = {
                treesitter = ["lsp"];
                # 颜色类的补全项(tailwind 的类名、cssls 的颜色值)用一个上色的
                # ■ 顶掉 kind 图标。highlight-colors 是 DeferredUIEnter 懒加载
                # 的,这里只用 pcall 取,取不到就退回默认图标 —— 不 require 硬拉,
                # 免得把它提前唤醒。
                components.kind_icon = {
                  text = mkRaw ''
                    function(ctx)
                      local icon = ctx.kind_icon
                      if ctx.source_name == "LSP" then
                        local ok, hl_colors = pcall(require, "nvim-highlight-colors")
                        if ok then
                          local color_item = hl_colors.format(ctx.item.documentation, { kind = ctx.kind })
                          if color_item and color_item.abbr ~= "" then
                            icon = color_item.abbr
                          end
                        end
                      end
                      return icon .. ctx.icon_gap
                    end
                  '';
                  # 保留 blink 默认的 priority 20000,否则光标行上会被
                  # CursorLine 盖掉。
                  highlight = mkRaw ''
                    function(ctx)
                      local group = ctx.kind_hl
                      if ctx.source_name == "LSP" then
                        local ok, hl_colors = pcall(require, "nvim-highlight-colors")
                        if ok then
                          local color_item = hl_colors.format(ctx.item.documentation, { kind = ctx.kind })
                          if color_item and color_item.abbr_hl_group then
                            group = color_item.abbr_hl_group
                          end
                        end
                      end
                      return { { group = group, priority = 20000 } }
                    end
                  '';
                };
              };
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
          sources = {
            default = [
              "lsp"
              "path"
              "snippets"
              "buffer"
            ];
            # blink 只扫 `stdpath('config')/snippets` 和 rtp 里名字匹配
            # `friendly.snippets` 的目录。nixvim 把 stdpath('config') 从 rtp
            # 里摘掉了,extraFiles 生成的目录又叫 nvim-config —— 两条都不匹配,
            # 所以自带的 snippets 必须把 store 路径直接喂给它。
            providers.snippets.opts.search_paths = ["${./nvim-snippets}"];
          };
          fuzzy.implementation = "prefer_rust_with_warning";
        };
      };

      rustaceanvim = {
        enable = dev;
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

      haskell-tools = {
        enable = dev;
        # Don't bundle HLS+GHC (~5 GiB) into the editor closure; use HLS from
        # a per-project devshell (found on PATH) instead.
        hlsPackage = null;
      };

      cornelis.enable = dev;

      lean = {
        enable = dev;
        lazyLoad.settings.ft = "lean";
        settings = {
          mappings = true;
          infoview = {
            orientation = "vertical";
            width = 40;
          };
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
        enable = dev;
        lintersByFt = {
          swift = ["swiftlint"];
          python = ["ruff"];
          haskell = ["hlint"];
        };
        autoCmd = {
          # BufReadPost 而不是 BufEnter:打开文件时 lint 一次就够了,
          # BufEnter 会在每次切 buffer 时都 spawn 一遍 linter。
          event = [
            "BufReadPost"
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
          # biome-check = `check --write`:格式化 + 整理 import + 只应用 safe fix。
          # 不用 --unsafe —— 那是一刀切的,会连 `==` 改 `===`、删未用 import 一起
          # 放进来。需要 unsafe fix 的规则(比如 tailwind 类名排序)由项目自己在
          # biome.json 里按规则写 `"fix": "safe"` 放行,见
          # docs/decisions.md#nixvim-no-tailwind-tools。
          formatters_by_ft = {
            swift = ["swiftformat"];
            typst = ["typstyle"];
            json = ["biome"];
            html = ["biome"];
            css = ["biome"];
            markdown = ["biome"];
            javascript = ["biome-check"];
            javascriptreact = ["biome-check"];
            typescript = ["biome-check"];
            typescriptreact = ["biome-check"];
            haskell = ["ormolu"];
            ocaml = ["ocamlformat"];
            python = ["ruff"];
            nix = ["alejandra"];
            elm = ["elm_format"];
          };
        };
      };

      typst-preview = {
        enable = dev;
        lazyLoad.settings.ft = "typst";
        settings = {};
      };

      diffview = {
        enable = true;
        lazyLoad.settings.cmd = [
          "DiffviewOpen"
          "DiffviewClose"
          "DiffviewToggleFiles"
          "DiffviewFocusFiles"
          "DiffviewRefresh"
          "DiffviewFileHistory"
        ];
      };

      markview = {
        enable = true;
        lazyLoad.settings.ft = ["markdown" "md"];
      };

      todo-comments = {
        enable = true;
        lazyLoad.settings.event = "DeferredUIEnter";
      };

      # 不跟 dev 走:改 token-theme 之类的 nix 文件时一样要看十六进制。
      highlight-colors = {
        enable = true;
        lazyLoad.settings.event = "DeferredUIEnter";
        settings = {
          # virtual:补一个 ■,不去动原文本的语法高亮。
          render = "virtual";
          virtual_symbol = "■";
          virtual_symbol_prefix = " ";
          virtual_symbol_suffix = "";
          # eow = 结束列,符号落在 token 之后。tailwind 那边靠自定义 style
          # 函数对齐到同一侧,见上面的 extraConfigLuaPre。
          virtual_symbol_position = "eow";
          # tailwind 类名归 tailwind-tools 走 LSP。这里的实现是内置静态表,
          # 而且相邻两个颜色类只会画一个(`bg-sky-500 text-slate-100` 这种
          # React 里最常见的写法就会漏),不能用。
          enable_tailwind = false;
        };
      };
    };

    # 顶层 lsp.* 模块(不在 plugins 下面)。plugins.lsp 是转发到这里的兼容层,
    # 上游标着 "will be removed when plugins.lsp is dropped"。
    lsp = {
      servers =
        {
          # "*" = 所有 server 共享的默认值。blink 的 capabilities 原来靠
          # plugins.lsp.capabilities 注入,那条路只在 plugins.lsp.enable 为真时
          # 才生成 __wrapConfig,迁走之后必须走这里。
          "*".config.capabilities = mkRaw ''require("blink-cmp").get_lsp_capabilities(nil, true)'';
        }
        // lib.mapAttrs (_: srv: {
          enable = true;
          # 不在这里 vim.lsp.enable,交给上面 external-lsp 那个 VimEnter 守卫:
          # PATH 上没有这个可执行文件就不启动,免得 nvim 去 spawn 一个不存在的
          # 进程然后报错。
          activate = false;
          # nixvim 一个 LSP 都不装。装在 home/profiles/dev.nix 里,项目 devshell
          # 可以再覆盖 —— package = null 意味着 nixvim 不往 PATH 里塞东西,
          # 于是顺序就是 devshell > home profile,天然是对的。
          package = null;
          config = srv.config or {};
        })
        externalServers;

      keymaps = [
        # 这六个原来是 plugins.lsp.keymaps.lspBuf,mode "n" + silent。
        {
          mode = "n";
          key = "gd";
          lspBufAction = "definition";
          options.silent = true;
        }
        {
          mode = "n";
          key = "gD";
          lspBufAction = "declaration";
          options.silent = true;
        }
        {
          mode = "n";
          key = "gr";
          lspBufAction = "references";
          options.silent = true;
        }
        {
          mode = "n";
          key = "gi";
          lspBufAction = "implementation";
          options.silent = true;
        }
        {
          mode = "n";
          key = "<leader>lr";
          lspBufAction = "rename";
          options.silent = true;
        }
        {
          mode = "n";
          key = "<leader>la";
          lspBufAction = "code_action";
          options.silent = true;
        }

        # 下面四个原来是 plugins.lsp.keymaps.extra。那边的默认 mode 是 ""
        # (normal + visual + operator-pending),这里原样保留,迁移不改行为。
        {
          mode = "";
          key = "<leader>ld";
          action = mkRaw ''
            function()
              vim.diagnostic.open_float()
            end
          '';
          options.desc = "LSP: Hover diagnostic";
        }
        {
          mode = "";
          key = "gh";
          action = mkRaw ''
            function()
              vim.lsp.buf.typehierarchy()
            end
          '';
          options.desc = "LSP: Goto type hierarchy";
        }
        {
          mode = "";
          key = "K";
          action = mkRaw ''
            function()
              vim.lsp.buf.hover({ border = "rounded" })
            end
          '';
          options.desc = "LSP: Hover";
        }
        {
          mode = "";
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

    # 内置 document_color 的渲染把 extmark 写死在 range 起始列,只能画在
    # token 前面。style 传函数就由我们接管渲染,才能和 highlight-colors 的
    # eow 一样落在 token 之后。代价:自定义函数下内置不再提供 hl_group,
    # 高亮组和 extmark 清理都得自己管。
    extraConfigLuaPre = ''
      do
        local ns = vim.api.nvim_create_namespace("hank_lsp_document_color")
        -- 内置逻辑每个 buffer version 只 apply 一批,所以拿 changedtick 判批次:
        -- 一批里第一次调用时清空整个 namespace,避免删掉颜色后留下残影。
        local applied = {}

        function _G.__hank_lsp_color_swatch(bufnr, range, hex_code)
          local tick = vim.api.nvim_buf_get_changedtick(bufnr)
          if applied[bufnr] ~= tick then
            vim.api.nvim_buf_clear_namespace(bufnr, ns, 0, -1)
            applied[bufnr] = tick
          end

          local group = "HankLspColor" .. hex_code:gsub("#", "")
          vim.api.nvim_set_hl(0, group, { fg = hex_code, default = true })
          vim.api.nvim_buf_set_extmark(bufnr, ns, range.end_row, range.end_col, {
            virt_text = { { " ■", group } },
            virt_text_pos = "inline",
          })
        end
      end
    '';

    extraConfigLuaPost = ''
      -- nvim 0.11+ 内置了 grn/gra/grr/gri/grt。我们自己用的是 gr/gi 和
      -- <leader>lr/<leader>la,功能完全重复;留着它们只会让 gr 每次都要等满
      -- timeoutlen(300ms)去分辨后面还有没有 r/a/n/i/t。
      for _, key in ipairs({ "grn", "gra", "grr", "gri", "grt" }) do
        pcall(vim.keymap.del, "n", key)
      end

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
