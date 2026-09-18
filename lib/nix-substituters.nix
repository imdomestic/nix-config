{useChinaMirror ? true}:
(
  if useChinaMirror
  then ["https://mirror.sjtu.edu.cn/nix-channels/store?priority=10"]
  else []
)
++ [
  "https://cache.nixos.org?priority=20"
  # cache.garnix.io 拿掉了。唯一走 garnix CI 的 input 是 nix-index-database,
  # 而它的全部产物就是两个 fetchurl(FOD,内容寻址,直接从 GitHub release 下)
  # 加几个 symlinkJoin wrapper(本地瞬间就建完)—— 一个都不靠它。留着的净效果
  # 只是每次求值多打一轮 narinfo,而它一 502 就能把整个构建拖停。
  # 自建 cache。里面只有 cache.nixos.org 一定没有的那几条:rpi4 被
  # nixos-hardware 改过的内核、mihomo-smart、自制字体。
  # 内容清单见 flake.nix 的 packages 输出,推送在 .github/workflows/cachix.yml。
  # 排在官方源之后:能命中的就那几条路径,让 sjtu/官方先答更划算。
  "https://imdomestic.cachix.org?priority=30"
  "https://cache.iog.io?priority=40"
  "https://cache.nixos-cuda.org?priority=50"
  # llm-agents(cli-proxy-api)。这个 flake 自己的 nixConfig 里声明了这个
  # substituter,但 flake input 的 nixConfig 不会被应用,只有把它当顶层 flake
  # 跑才会提示 --accept-flake-config,所以必须在这里显式写一遍。
  # 少了它,llm-agents 就得在本地从源码编 —— 那正是不 follows 我们 nixpkgs
  # 的全部意义所在。
  "https://cache.numtide.com?priority=60"
  "https://devenv.cachix.org"
]
