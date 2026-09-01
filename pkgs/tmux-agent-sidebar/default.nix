{
  lib,
  rustPlatform,
  fetchFromGitHub,
}:
# 跨 tmux session/window 监控 Claude Code / Codex / OpenCode 的侧边栏 TUI。
#
# 上游只给 TPM 装法,而那条路在 Nix 下走不通:tmux-agent-sidebar.tmux 找不到
# 二进制就跑 install-wizard.sh,向导要往 $PLUGIN_DIR/bin/ 写一个从 GitHub
# Release 下载的二进制 —— store 是只读的。所以这里自己编,并且把 bin/ 摆进
# 插件目录,让上游那个脚本的第一条查找路径直接命中,一次都不会走到向导。
rustPlatform.buildRustPackage (finalAttrs: {
  # 前缀不是随手加的:home-manager 的 programs.tmux 有一条断言,插件的包名必须
  # 以 `tmuxplugin` 开头(它照 nixpkgs 里 mkTmuxPlugin 的命名约定来的),否则
  # 求值直接失败。二进制本身仍然叫 tmux-agent-sidebar。
  pname = "tmuxplugin-agent-sidebar";
  version = "0.13.0";

  src = fetchFromGitHub {
    owner = "hiroppy";
    repo = "tmux-agent-sidebar";
    tag = "v${finalAttrs.version}";
    hash = "sha256-NiqLgMvWbSW3M80ZUWdmmm2VkVqy8eTGcPkrOCsaasI=";
  };

  cargoHash = "sha256-mOEs2J1o9VeVOXY55r8O52TqoM2GuYU3tVoh5h+yH0s=";

  # 依赖里没有 C 库:剪贴板走 arboard,darwin 上是 objc2-app-kit(链系统
  # framework,26.05 的 stdenv 已经带 SDK),Linux 上是 x11rb 的纯 Rust
  # rust-connection,都不需要额外 buildInputs。

  postInstall = ''
    plugindir=$out/share/tmux-plugins/tmux-agent-sidebar
    mkdir -p $plugindir/bin

    # tmux 那边要的三样:入口脚本、它 source 的 conf、以及 Cargo.toml ——
    # 入口脚本会拿 `$BIN version` 和 Cargo.toml 里的 version 比对,对不上就
    # 弹安装向导。两者出自同一个 src,所以这个比对恒真。
    cp tmux-agent-sidebar.tmux agent-sidebar.conf Cargo.toml $plugindir/

    # Claude Code 那边要的:hook.sh 是个薄壳,每次触发才现场找二进制;
    # .claude-plugin/ 和 hooks/ 让这个目录同时能当 plugin marketplace 用。
    cp hook.sh $plugindir/
    cp -r .claude-plugin hooks $plugindir/

    ln -s $out/bin/tmux-agent-sidebar $plugindir/bin/tmux-agent-sidebar
  '';

  # 测试照跑(1022 条通过),只跳掉两条:它们要在一个**真的 git 仓库**里跑
  # (group.rs:175 / :192 断言 "should detect git repo"),而 fetchFromGitHub
  # 拿到的是 tarball,没有 .git。剩下的都是纯逻辑,值得当构建期的护栏。
  checkFlags = [
    "--skip=group::tests::resolve_git_info_for_real_repo"
    "--skip=group::tests::worktree_and_main_share_same_repo_root"
  ];

  # home-manager 的 programs.tmux.plugins 认的是 `rtp`(它照着这个值写
  # `run-shell <rtp>`),而 rtp 平时由 tmuxPlugins.mkTmuxPlugin 生成 ——
  # 我们没走那条路,所以自己补一个,指向上游的入口脚本。
  passthru.rtp = "${finalAttrs.finalPackage}/share/tmux-plugins/tmux-agent-sidebar/tmux-agent-sidebar.tmux";

  meta = {
    description = "tmux sidebar that monitors AI coding agents across all windows and sessions";
    homepage = "https://github.com/hiroppy/tmux-agent-sidebar";
    license = lib.licenses.mit;
    mainProgram = "tmux-agent-sidebar";
    platforms = lib.platforms.unix;
  };
})
