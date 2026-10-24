{
  inputs,
  lib,
  ...
}: let
  mkRaw = inputs.nixvim.lib.nixvim.mkRaw;
in {
  # plugins.jdtls.settings.cmd 只接受列表;原生 LSP 选项支持按项目生成命令。
  programs.nixvim.lsp.servers.jdtls.config.cmd = lib.mkForce (mkRaw ''
    function(dispatchers, config)
      local root = config.root_dir or vim.fn.getcwd()
      local workspace = vim.fn.stdpath("cache") .. "/jdtls/" .. vim.fn.sha256(root)
      return vim.lsp.rpc.start({ "jdtls", "-data", workspace }, dispatchers, {
        cwd = root,
      })
    end
  '');

  # jdtls 的 hover 把 Javadoc 的 {@link} 写成几百字符的 jdt://contents/... 链接。
  # 浮窗按原始长度算宽度,隐藏的链接在折行时照样占位,于是窗口顶满屏宽、
  # 句号被挤到下一行、底部多出空行。弹窗前把链接换成纯文字,顺带去掉 \< \>。
  programs.nixvim.autoGroups.jdtls-hover.clear = true;
  programs.nixvim.autoCmd = [
    {
      event = "LspAttach";
      group = "jdtls-hover";
      desc = "Hover for jdtls without jdt:// link targets";
      callback = mkRaw ''
        function(args)
          local client = vim.lsp.get_client_by_id(args.data.client_id)
          if not client or client.name ~= "jdtls" then
            return
          end
          vim.keymap.set("n", "K", function()
            local params = vim.lsp.util.make_position_params(0, client.offset_encoding)
            client:request("textDocument/hover", params, function(err, result)
              if err or not (result and result.contents) then
                return
              end
              local md = table.concat(vim.lsp.util.convert_input_to_markdown_lines(result.contents), "\n")
              md = md:gsub("%[([^%]]*)%]%b()", "%1"):gsub("\\([<>])", "%1")
              vim.lsp.util.open_floating_preview(vim.split(vim.trim(md), "\n"), "markdown", {
                focus_id = "textDocument/hover",
              })
            end, args.buf)
          end, { buffer = args.buf, desc = "Hover documentation" })
        end
      '';
    }
  ];

  programs.nixvim.plugins.jdtls = {
    enable = true;
    # 由 Hank 的 dev profile 提供,允许项目 devshell 覆盖。
    jdtLanguageServerPackage = null;
    settings = {
      root_markers = [
        ["gradlew" "mvnw" "settings.gradle" "settings.gradle.kts"]
        ["build.gradle" "build.gradle.kts" "pom.xml"]
        ".git"
      ];
      settings.java = {
        configuration.updateBuildConfiguration = "interactive";
        eclipse.downloadSources = true;
        maven.downloadSources = true;
        signatureHelp.enabled = true;
        sources.organizeImports = {
          starThreshold = 9999;
          staticStarThreshold = 9999;
        };
      };
    };
  };
}
