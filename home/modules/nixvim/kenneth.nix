{
  config,
  inputs,
  lib,
  pkgs,
  ...
}: let
  mkRaw = inputs.nixvim.lib.nixvim.mkRaw;
  javaDebugServer = "${pkgs.vscode-extensions.vscjava.vscode-java-debug}/share/vscode/extensions/vscjava.vscode-java-debug/server";
  javaTestServer = "${pkgs.vscode-extensions.vscjava.vscode-java-test}/share/vscode/extensions/vscjava.vscode-java-test/server";
  vscodeLldbExt = "${pkgs.vscode-extensions.vadimcn.vscode-lldb}/share/vscode/extensions/vadimcn.vscode-lldb";
in {
  imports = [./default.nix];

  programs.nixvim = {
    globals.maplocalleader = lib.mkForce ",";

    opts = {
      confirm = true;
      copyindent = true;
      expandtab = true;
      foldcolumn = "1";
      linebreak = true;
      preserveindent = true;
      pumheight = 10;
      relativenumber = true;
      shiftwidth = 2;
      tabstop = 2;
      virtualedit = "block";
      wrap = false;
      writebackup = false;
    };

    extraPackages = with pkgs; [
      cargo
      jdk21
      rustc
      rustfmt
      stylua
    ];

    autoGroups = {
      kenneth-jdtls-dap.clear = true;
      kenneth-lsp-codelens.clear = true;
    };

    autoCmd = [
      {
        event = [
          "BufEnter"
          "CursorHold"
          "InsertLeave"
        ];
        group = "kenneth-lsp-codelens";
        desc = "Refresh LSP code lenses";
        callback = mkRaw ''
          function(args)
            for _, client in ipairs(vim.lsp.get_clients({ bufnr = args.buf })) do
              if client.server_capabilities.codeLensProvider then
                pcall(vim.lsp.codelens.refresh, { bufnr = args.buf })
                return
              end
            end
          end
        '';
      }
      {
        event = "LspAttach";
        group = "kenneth-jdtls-dap";
        desc = "Load Java main-class DAP configurations";
        callback = mkRaw ''
          function(args)
            local client = vim.lsp.get_client_by_id(args.data.client_id)
            if client and client.name == "jdtls" then
              require("jdtls.dap").setup_dap_main_class_configs()
            end
          end
        '';
      }
    ];

    keymaps = lib.mkAfter [
      {
        mode = "n";
        key = "gl";
        action = mkRaw ''
          function()
            vim.diagnostic.open_float()
          end
        '';
        options.desc = "Hover diagnostics";
      }
      {
        mode = "n";
        key = "<F5>";
        action = mkRaw ''function() require("dap").continue() end'';
        options.desc = "Debugger: Start";
      }
      {
        mode = "n";
        key = "<F17>";
        action = mkRaw ''function() require("dap").terminate() end'';
        options.desc = "Debugger: Stop";
      }
      {
        mode = "n";
        key = "<F21>";
        action = mkRaw ''
          function()
            vim.ui.input({ prompt = "Condition: " }, function(condition)
              if condition then require("dap").set_breakpoint(condition) end
            end)
          end
        '';
        options.desc = "Debugger: Conditional Breakpoint";
      }
      {
        mode = "n";
        key = "<F29>";
        action = mkRaw ''function() require("dap").restart_frame() end'';
        options.desc = "Debugger: Restart";
      }
      {
        mode = "n";
        key = "<F6>";
        action = mkRaw ''function() require("dap").pause() end'';
        options.desc = "Debugger: Pause";
      }
      {
        mode = "n";
        key = "<F9>";
        action = mkRaw ''function() require("dap").toggle_breakpoint() end'';
        options.desc = "Debugger: Toggle Breakpoint";
      }
      {
        mode = "n";
        key = "<F10>";
        action = mkRaw ''function() require("dap").step_over() end'';
        options.desc = "Debugger: Step Over";
      }
      {
        mode = "n";
        key = "<F11>";
        action = mkRaw ''function() require("dap").step_into() end'';
        options.desc = "Debugger: Step Into";
      }
      {
        mode = "n";
        key = "<F23>";
        action = mkRaw ''function() require("dap").step_out() end'';
        options.desc = "Debugger: Step Out";
      }
      {
        mode = "n";
        key = "<leader>db";
        action = mkRaw ''function() require("dap").toggle_breakpoint() end'';
        options.desc = "Toggle Breakpoint";
      }
      {
        mode = "n";
        key = "<leader>dB";
        action = mkRaw ''function() require("dap").clear_breakpoints() end'';
        options.desc = "Clear Breakpoints";
      }
      {
        mode = "n";
        key = "<leader>dc";
        action = mkRaw ''function() require("dap").continue() end'';
        options.desc = "Start/Continue";
      }
      {
        mode = "n";
        key = "<leader>dC";
        action = mkRaw ''
          function()
            vim.ui.input({ prompt = "Condition: " }, function(condition)
              if condition then require("dap").set_breakpoint(condition) end
            end)
          end
        '';
        options.desc = "Conditional Breakpoint";
      }
      {
        mode = "n";
        key = "<leader>di";
        action = mkRaw ''function() require("dap").step_into() end'';
        options.desc = "Step Into";
      }
      {
        mode = "n";
        key = "<leader>do";
        action = mkRaw ''function() require("dap").step_over() end'';
        options.desc = "Step Over";
      }
      {
        mode = "n";
        key = "<leader>dO";
        action = mkRaw ''function() require("dap").step_out() end'';
        options.desc = "Step Out";
      }
      {
        mode = "n";
        key = "<leader>dq";
        action = mkRaw ''function() require("dap").close() end'';
        options.desc = "Close Session";
      }
      {
        mode = "n";
        key = "<leader>dQ";
        action = mkRaw ''function() require("dap").terminate() end'';
        options.desc = "Terminate Session";
      }
      {
        mode = "n";
        key = "<leader>dp";
        action = mkRaw ''function() require("dap").pause() end'';
        options.desc = "Pause";
      }
      {
        mode = "n";
        key = "<leader>dr";
        action = mkRaw ''function() require("dap").restart_frame() end'';
        options.desc = "Restart Frame";
      }
      {
        mode = "n";
        key = "<leader>dR";
        action = mkRaw ''function() require("dap").repl.toggle() end'';
        options.desc = "Toggle REPL";
      }
      {
        mode = "n";
        key = "<leader>ds";
        action = mkRaw ''function() require("dap").run_to_cursor() end'';
        options.desc = "Run To Cursor";
      }
      {
        mode = "n";
        key = "<leader>du";
        action = mkRaw ''function() require("dapui").toggle() end'';
        options.desc = "Toggle Debugger UI";
      }
      {
        mode = "n";
        key = "<leader>dh";
        action = mkRaw ''function() require("dap.ui.widgets").hover() end'';
        options.desc = "Debugger Hover";
      }
      {
        mode = "n";
        key = "<leader>dE";
        action = mkRaw ''
          function()
            vim.ui.input({ prompt = "Expression: " }, function(expression)
              if expression then require("dapui").eval(expression, { enter = true }) end
            end)
          end
        '';
        options.desc = "Evaluate Input";
      }
      {
        mode = "v";
        key = "<leader>dE";
        action = mkRaw ''function() require("dapui").eval() end'';
        options.desc = "Evaluate Selection";
      }
    ];

    plugins = {
      presence.enable = true;
      lsp-signature.enable = true;

      dap = {
        enable = true;
        signs = {
          dapBreakpoint = {
            text = "";
            texthl = "DiagnosticInfo";
          };
          dapBreakpointCondition = {
            text = "";
            texthl = "DiagnosticInfo";
          };
          dapBreakpointRejected = {
            text = "";
            texthl = "DiagnosticError";
          };
          dapLogPoint = {
            text = ".>";
            texthl = "DiagnosticInfo";
          };
          dapStopped = {
            text = "󰁕";
            texthl = "DiagnosticWarn";
          };
        };
      };

      dap-ui = {
        enable = true;
        settings.floating.border = "rounded";
      };

      alpha = {
        enable = true;
        settings = mkRaw ''
          (function()
            local dashboard = require("alpha.themes.dashboard")
            dashboard.section.header.val = {
              "██╗  ██╗███████╗███╗   ██╗███╗   ██╗███████╗████████╗██╗  ██╗",
              "██║ ██╔╝██╔════╝████╗  ██║████╗  ██║██╔════╝╚══██╔══╝██║  ██║",
              "█████╔╝ █████╗  ██╔██╗ ██║██╔██╗ ██║█████╗     ██║   ███████║",
              "██╔═██╗ ██╔══╝  ██║╚██╗██║██║╚██╗██║██╔══╝     ██║   ██╔══██║",
              "██║  ██╗███████╗██║ ╚████║██║ ╚████║███████╗   ██║   ██║  ██║",
              "╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝",
            }
            return dashboard.config
          end)()
        '';
      };

      luasnip = {
        enable = true;
        filetypeExtend.javascript = ["javascriptreact"];
      };

      blink-cmp.settings = {
        sources = {
          default = lib.mkForce [
            "lsp"
            "path"
            "luasnip"
            "buffer"
          ];
          providers.luasnip = {
            name = "LuaSnip";
            module = "blink.cmp.sources.luasnip";
            score_offset = -3;
          };
        };
        snippets = {
          expand = mkRaw ''
            function(snippet)
              require("luasnip").lsp_expand(snippet)
            end
          '';
          active = mkRaw ''
            function(filter)
              if filter and filter.direction then
                return require("luasnip").jumpable(filter.direction)
              end
              return require("luasnip").in_snippet()
            end
          '';
          jump = mkRaw ''
            function(direction)
              require("luasnip").jump(direction)
            end
          '';
        };
      };

      lsp.servers = {
        lua_ls = {
          enable = lib.mkForce true;
          settings = {
            hint = {
              enable = true;
              arrayIndex = "Disable";
            };
            format.enable = false;
          };
        };
        taplo.enable = lib.mkForce true;
        lemminx = {
          enable = true;
          packageFallback = true;
        };
      };

      rustaceanvim = {
        enable = lib.mkForce true;
        settings = {
          dap = {
            autoload_configurations = true;
            adapter = mkRaw ''
              require("rustaceanvim.config").get_codelldb_adapter(
                "${vscodeLldbExt}/adapter/codelldb",
                "${vscodeLldbExt}/lldb/lib/liblldb.so"
              )
            '';
          };
          server.default_settings."rust-analyzer" = {
            assist = {
              importEnforceGranularity = true;
              importPrefix = "crate";
            };
            completion.postfix.enable = false;
            inlayHints.lifetimeElisionHints = {
              enable = "always";
              useParameterNames = true;
            };
          };
        };
      };

      crates = {
        enable = true;
        settings = {};
      };

      jdtls = {
        enable = true;
        jdtLanguageServerPackage = pkgs.jdt-language-server;
        settings = {
          init_options.bundles = mkRaw ''
            (function()
              local bundles = vim.fn.glob("${javaDebugServer}/*.jar", false, true)
              vim.list_extend(
                bundles,
                vim.fn.glob("${javaTestServer}/*.jar", false, true)
              )
              return bundles
            end)()
          '';
          on_attach = mkRaw ''
            function(_, _)
              require("jdtls").setup_dap({ hotcodereplace = "auto" })
            end
          '';
          root_dir = mkRaw ''
            require("jdtls.setup").find_root({
              ".git",
              "mvnw",
              "gradlew",
              "pom.xml",
              "build.gradle",
              ".project",
            })
          '';
          settings = {
            java = {
              eclipse.downloadSources = true;
              configuration.updateBuildConfiguration = "interactive";
              maven.downloadSources = true;
              implementationsCodeLens.enabled = true;
              referencesCodeLens.enabled = true;
            };
            signatureHelp.enabled = true;
            completion.favoriteStaticMembers = [
              "org.hamcrest.MatcherAssert.assertThat"
              "org.hamcrest.Matchers.*"
              "org.hamcrest.CoreMatchers.*"
              "org.junit.jupiter.api.Assertions.*"
              "java.util.Objects.requireNonNull"
              "java.util.Objects.requireNonNullElse"
              "org.mockito.Mockito.*"
            ];
            sources.organizeImports = {
              starThreshold = 9999;
              staticStarThreshold = 9999;
            };
          };
        };
      };

      treesitter.grammarPackages = lib.mkAfter (
        with config.programs.nixvim.plugins.treesitter.package.builtGrammars; [
          html
          java
          luap
          rust
        ]
      );

      conform-nvim.settings = {
        format_on_save = lib.mkForce {
          timeout_ms = 1000;
          lsp_format = "fallback";
        };
        formatters_by_ft.lua = ["stylua"];
        formatters.stylua.prepend_args = [
          "--column-width"
          "120"
          "--line-endings"
          "Unix"
          "--indent-type"
          "Spaces"
          "--indent-width"
          "2"
          "--quote-style"
          "AutoPreferDouble"
          "--call-parentheses"
          "None"
          "--collapse-simple-statement"
          "Always"
        ];
      };
    };

    extraConfigLuaPost = lib.mkAfter ''
      do
        local dap = require("dap")
        local dapui = require("dapui")

        dap.listeners.after.event_initialized["kenneth_dapui"] = function()
          dapui.open()
        end
        dap.listeners.before.event_terminated["kenneth_dapui"] = function()
          dapui.close()
        end
        dap.listeners.before.event_exited["kenneth_dapui"] = function()
          dapui.close()
        end
      end
    '';
  };
}
