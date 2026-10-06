# linwhite = base.nix 那套 + 输入法自动切换(macOS)。
{
  inputs,
  lib,
  pkgs,
  pkgs-unstable,
  ...
}: let
  mkRaw = inputs.nixvim.lib.nixvim.mkRaw;
  javaDebugServer = "${pkgs.vscode-extensions.vscjava.vscode-java-debug}/share/vscode/extensions/vscjava.vscode-java-debug/server";
  javaTestServer = "${pkgs.vscode-extensions.vscjava.vscode-java-test}/share/vscode/extensions/vscjava.vscode-java-test/server";
in {
  imports = [./base.nix];

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

    # chorus 工作流：jdtls 走 devenv 里 JDK 25 的 jdtls（PATH 守卫在
    # base.nix 的 lsp.servers.jdtls.exe），调试 bundles 用仓库里的
    # vscode-java-debug / java-test jar。
    plugins = {
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

      jdtls = {
        enable = true;
        jdtLanguageServerPackage = null;
        settings = {
          # jdtls 自己的堆：带着 Minecraft 类路径 2G 会顶满，encore 24G 给 3G
          cmd_env.JDK_JAVA_OPTIONS = "-Xmx3g -XX:+UseG1GC";
          # multiloader 是 Gradle 多项目：以 gradlew 所在目录为 root
          root_dir = mkRaw ''
            require("jdtls.setup").find_root({
              "gradlew",
              ".git",
              "mvnw",
              "pom.xml",
              "build.gradle",
              ".project",
            })
          '';
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
              -- 保存 → jdtls 增量编译 → 热替换进正在跑的 MC（标准 JVM 只能改方法体）
              require("jdtls").setup_dap({ hotcodereplace = "auto" })

              local dap = require("dap")
              dap.configurations.java = {
                {
                  type = "java",
                  request = "attach",
                  name = "Attach: encore 本机客户端 (5005)",
                  hostName = "127.0.0.1",
                  port = 5005,
                },
                {
                  type = "java",
                  request = "attach",
                  name = "Attach: 9950X 服务端 (隧道 5006)",
                  hostName = "127.0.0.1",
                  port = 5006,
                },
              }
            end
          '';
          settings = {
            java = {
              import.gradle = {
                enabled = true;
                # 用仓库自带的 Gradle wrapper
                wrapper.enabled = true;
                # Gradle JVM 必须是 devenv 的 JDK 25
                java.home = mkRaw ''os.getenv("JAVA_HOME")'';
              };
              configuration = {
                updateBuildConfiguration = "interactive";
                runtimes = mkRaw ''
                  (function()
                    local java_home = os.getenv("JAVA_HOME")
                    if java_home then
                      return { { name = "JavaSE-25", path = java_home, default = true } }
                    end
                  end)()
                '';
              };
              # 跳进没有源码的 class 时用 fernflower 反编译
              contentProvider.preferred = "fernflower";
              eclipse.downloadSources = true;
              maven.downloadSources = true;
            };
          };
        };
      };
    };

    keymaps = lib.mkAfter [
      {
        mode = "n";
        key = "<leader>dc";
        action = mkRaw ''function() require("dap").continue() end'';
        options.desc = "DAP: attach / 继续";
      }
      {
        mode = "n";
        key = "<leader>db";
        action = mkRaw ''function() require("dap").toggle_breakpoint() end'';
        options.desc = "DAP: 断点";
      }
      {
        mode = "n";
        key = "<leader>do";
        action = mkRaw ''function() require("dap").step_over() end'';
        options.desc = "DAP: 单步跳过";
      }
      {
        mode = "n";
        key = "<leader>di";
        action = mkRaw ''function() require("dap").step_into() end'';
        options.desc = "DAP: 单步进入";
      }
      {
        mode = "n";
        key = "<leader>dr";
        action = mkRaw ''function() require("dap").repl.open() end'';
        options.desc = "DAP: REPL";
      }
      {
        mode = "n";
        key = "<leader>dq";
        action = mkRaw ''
          function()
            -- 只断开调试器，不杀游戏
            require("dap").disconnect({ terminateDebuggee = false })
          end
        '';
        options.desc = "DAP: 断开";
      }
      {
        mode = "n";
        key = "<leader>du";
        action = mkRaw ''function() require("dapui").toggle() end'';
        options.desc = "Toggle Debugger UI";
      }
    ];

    extraConfigLuaPost = lib.mkAfter ''
      do
        local dap = require("dap")
        local dapui = require("dapui")

        dap.listeners.after.event_initialized["linwhite_dapui"] = function()
          dapui.open()
        end
        dap.listeners.before.event_terminated["linwhite_dapui"] = function()
          dapui.close()
        end
        dap.listeners.before.event_exited["linwhite_dapui"] = function()
          dapui.close()
        end
      end
    '';
  };
}
