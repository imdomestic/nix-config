# 运营网络镜像的 tag：这个目录（git 跟踪的文件）的内容哈希。
#
# CI 构建镜像时用 `nix eval --raw .#mcImageTag` 拿 tag，nixidy 渲染时 import 这个文件，
# 两边算出来的是同一个值。源码不变 tag 就不变，也不需要机器人提交来改 tag。
# 取的是 store 路径里的哈希段：同样的内容和名字一定得到同一个路径。
builtins.substring 11 12 (toString (builtins.path {
  path = ./.;
  name = "minecraft-src";
}))
