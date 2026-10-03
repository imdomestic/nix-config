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
