# 调试:nvim-dap + dap-ui,界面和键位按 AstroNvim 的默认配置来。
# 适配器:C/C++/Rust 在 Linux 用 codelldb、在 macOS 用 Apple 的 lldb-dap
# (原因见 docs/incidents.md#codelldb-crashes-on-darwin);Java 走 jdtls 的
# java-debug/java-test 插件;
# Haskell 由 haskell-tools 在 attach 时自动发现配置,前提是项目 devshell 里
# 有和项目 GHC 匹配的 haskell-debug-adapter(和 HLS 一样不由这里安装)。
{
  inputs,
  lib,
  pkgs,
  ...
}: let
  mkRaw = inputs.nixvim.lib.nixvim.mkRaw;
  inherit (pkgs.stdenv.hostPlatform) isDarwin;
  vscodeExt = pkg: id: "${pkg}/share/vscode/extensions/${id}";
  javaDebug = "${vscodeExt pkgs.vscode-extensions.vscjava.vscode-java-debug "vscjava.vscode-java-debug"}/server";
  javaTest = "${vscodeExt pkgs.vscode-extensions.vscjava.vscode-java-test "vscjava.vscode-java-test"}/server";

  # 扩展目录里的 lldb 软链接让 codelldb 自己找到 liblldb,不用传 --liblldb。
  # nixvim 的 adapters.servers 自己补 type = "server",rustaceanvim 那份要显式带上。
  codelldbServer = {
    port = "\${port}";
    executable = {
      command = "${vscodeExt pkgs.vscode-extensions.vadimcn.vscode-lldb "vadimcn.vscode-lldb"}/adapter/codelldb";
      args = ["--port" "\${port}"];
    };
  };
  # xcrun 按当前生效的 Xcode / Command Line Tools 找 lldb-dap,换机器不用改路径。
  lldbDap = {
    command = "/usr/bin/xcrun";
    args = ["lldb-dap"];
  };
  lldbAdapter =
    if isDarwin
    then "lldb-dap"
    else "codelldb";

  lldbConfigurations = [
    {
      name = "Launch executable";
      type = lldbAdapter;
      request = "launch";
      program = mkRaw ''
        function()
          return vim.fn.input("Path to executable: ", vim.fn.getcwd() .. "/", "file")
        end
      '';
      cwd = "\${workspaceFolder}";
      stopOnEntry = false;
    }
    {
      name = "Attach to process";
      type = lldbAdapter;
      request = "attach";
      pid = mkRaw ''require("dap.utils").pick_process'';
      cwd = "\${workspaceFolder}";
    }
  ];

  dapCall = fn: ''function() require("dap").${fn}() end'';
  conditionalBreakpoint = ''
    function()
      vim.ui.input({ prompt = "Condition: " }, function(condition)
        if condition then require("dap").set_breakpoint(condition) end
      end)
    end
  '';
  # 经过 tmux 时 Shift/Ctrl+F5 这类组合到 nvim 是 <F17> 之类(tmux 的 terminfo),
  # 直接在 Ghostty 里可能是 <S-F5>,两种都映射。
  fkeys = keys: action: desc:
    map (key: {
      mode = "n";
      inherit key;
      action = mkRaw action;
      options.desc = desc;
    })
    keys;
  leader = key: action: desc: {
    mode = "n";
    key = "<leader>d${key}";
    action = mkRaw action;
    options.desc = desc;
  };

  # dap-repl 和 dap-ui 的输入框是 prompt buffer,blink 默认在 prompt 里不补全。
  dapFiletypes = ["dap-repl" "dapui_watches" "dapui_hover"];
in {
  programs.nixvim = {
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
            text = "󰛿";
            texthl = "DiagnosticInfo";
          };
          dapStopped = {
            text = "󰁕";
            texthl = "DiagnosticWarn";
          };
        };
        adapters =
          if isDarwin
          then {executables.lldb-dap = lldbDap;}
          else {servers.codelldb = codelldbServer;};
        configurations = {
          c = lldbConfigurations;
          cpp = lldbConfigurations;
        };
      };

      dap-ui = {
        enable = true;
        settings.floating.border = "rounded";
      };

      which-key.settings.spec = [
        {
          __unkeyed-1 = "<leader>d";
          group = "Debugger";
        }
      ];

      # REPL 和 watch 里的补全:cmp-dap 是 nvim-cmp 的源,经 blink.compat 接进 blink。
      blink-compat.enable = true;
      cmp-dap.enable = true;
      blink-cmp.settings = {
        enabled = mkRaw ''
          function()
            if vim.bo.buftype == "prompt" then
              return vim.tbl_contains(${inputs.nixvim.lib.nixvim.toLuaObject dapFiletypes}, vim.bo.filetype)
            end
            return vim.b.completion ~= false
          end
        '';
        sources = {
          providers.dap = {
            name = "dap";
            module = "blink.compat.source";
            score_offset = 100;
          };
          per_filetype = builtins.listToAttrs (map (ft: {
              name = ft;
              value = ["dap"];
            })
            dapFiletypes);
        };
      };

      # rustaceanvim 按 type 区分:server 当 codelldb,executable 当 lldb 并
      # 自动加载 rustc 自带的 LLDB 类型格式化命令。nixvim 把 executable 的
      # args 声明成了字符串,列表只能以 raw Lua 传。
      # macOS 上 rustaceanvim 给 lldb 默认的 console = "integratedTerminal" 会让
      # lldb-dap 的终端启动器超时退出,改成输出到 REPL。
      rustaceanvim.settings.dap =
        if isDarwin
        then {
          adapter = {
            type = "executable";
            name = "lldb";
            inherit (lldbDap) command;
            args = mkRaw ''{ "lldb-dap" }'';
          };
          configuration = {
            name = "Rust debug client";
            type = "lldb";
            request = "launch";
            stopOnEntry = false;
            console = "internalConsole";
          };
        }
        else {adapter = codelldbServer // {type = "server";};};

      # 有 java-debug 插件时 nvim-jdtls 在 attach 时自己调用 setup_dap,
      # 按 F5 时再向 jdtls 要 main class 列表。java-test 那两个 jar 按
      # nvim-jdtls README 的要求排除。
      jdtls.settings.init_options.bundles = mkRaw ''
        (function()
          local bundles = vim.fn.glob("${javaDebug}/com.microsoft.java.debug.plugin-*.jar", false, true)
          local excluded = { "com.microsoft.java.test.runner-jar-with-dependencies.jar", "jacocoagent.jar" }
          for _, jar in ipairs(vim.fn.glob("${javaTest}/*.jar", false, true)) do
            if not vim.tbl_contains(excluded, vim.fn.fnamemodify(jar, ":t")) then
              table.insert(bundles, jar)
            end
          end
          return bundles
        end)()
      '';
    };

    keymaps =
      fkeys ["<F5>"] (dapCall "continue") "Debugger: Start"
      ++ fkeys ["<F17>" "<S-F5>"] (dapCall "terminate") "Debugger: Stop"
      ++ fkeys ["<F29>" "<C-F5>"] (dapCall "restart_frame") "Debugger: Restart"
      ++ fkeys ["<F6>"] (dapCall "pause") "Debugger: Pause"
      ++ fkeys ["<F9>"] (dapCall "toggle_breakpoint") "Debugger: Toggle Breakpoint"
      ++ fkeys ["<F21>" "<S-F9>"] conditionalBreakpoint "Debugger: Conditional Breakpoint"
      ++ fkeys ["<F10>"] (dapCall "step_over") "Debugger: Step Over"
      ++ fkeys ["<F11>"] (dapCall "step_into") "Debugger: Step Into"
      ++ fkeys ["<F23>" "<S-F11>"] (dapCall "step_out") "Debugger: Step Out"
      ++ [
        (leader "b" (dapCall "toggle_breakpoint") "Toggle Breakpoint (F9)")
        (leader "B" (dapCall "clear_breakpoints") "Clear Breakpoints")
        (leader "c" (dapCall "continue") "Start/Continue (F5)")
        (leader "C" conditionalBreakpoint "Conditional Breakpoint (S-F9)")
        (leader "i" (dapCall "step_into") "Step Into (F11)")
        (leader "o" (dapCall "step_over") "Step Over (F10)")
        (leader "O" (dapCall "step_out") "Step Out (S-F11)")
        (leader "q" (dapCall "close") "Close Session")
        (leader "Q" (dapCall "terminate") "Terminate Session (S-F5)")
        (leader "p" (dapCall "pause") "Pause (F6)")
        (leader "r" (dapCall "restart_frame") "Restart (C-F5)")
        (leader "R" ''function() require("dap").repl.toggle() end'' "Toggle REPL")
        (leader "s" (dapCall "run_to_cursor") "Run To Cursor")
        (leader "u" ''function() require("dapui").toggle() end'' "Toggle Debugger UI")
        (leader "h" ''function() require("dap.ui.widgets").hover() end'' "Debugger Hover")
        (leader "E" ''
            function()
              vim.ui.input({ prompt = "Expression: " }, function(expr)
                if expr then require("dapui").eval(expr, { enter = true }) end
              end)
            end
          ''
          "Evaluate Input")
        {
          mode = "v";
          key = "<leader>dE";
          action = mkRaw ''function() require("dapui").eval() end'';
          options.desc = "Evaluate Selection";
        }
      ];

    # 会话开始自动打开 dap-ui,结束或进程退出时关掉。比 AstroNvim 多一条
    # disconnect:java-debug 不支持 terminate,S-F5 退化成 disconnect,
    # 不发 terminated/exited 事件,不加这条 dap-ui 会一直开着。
    extraConfigLua = ''
      do
        local dap, dapui = require("dap"), require("dapui")
        dap.listeners.after.event_initialized.dapui_config = function() dapui.open() end
        dap.listeners.before.event_terminated.dapui_config = function() dapui.close() end
        dap.listeners.before.event_exited.dapui_config = function() dapui.close() end
        dap.listeners.after.disconnect.dapui_config = function() dapui.close() end
      end
    '';
  };
}
