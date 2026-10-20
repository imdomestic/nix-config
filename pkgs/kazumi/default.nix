{
  lib,
  stdenvNoCC,
  fetchurl,
  _7zz,
}:
# Kazumi(Predidit/Kazumi)的 macOS 版。
#
# nixpkgs 里的 kazumi 只给 Linux(从源码用 Flutter 构建),macOS 上从源码编
# Flutter app 需要 Xcode,所以这里直接拿上游 Release 的 dmg 解包。官方 cask
# 仓库也没有它,走不了 homebrew.casks。
#
# 升级:改 version,hash 先置空跑一次 `just darwin aegis`,用报错里的值填回。
# App 内的自动更新只会下载 dmg 并 `open` 它,装出来的是 /Applications 里的另
# 一份副本,跟这里的版本对不上 —— 在 设置 → 更新 里把自动更新关掉,版本只在
# 这里升。
stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "kazumi";
  version = "2.3.9";

  src = fetchurl {
    url = "https://github.com/Predidit/Kazumi/releases/download/${finalAttrs.version}/Kazumi_macos_${finalAttrs.version}.dmg";
    hash = "sha256-Sx8Mhv0jte6ITVOGSqrHj5ezEX+ruUL/GNNR340MopA=";
  };

  # dmg 是 lzfse 压缩的 UDIF,7zz 能直接解;-snld 跳过 create-dmg 放进去的
  # /Applications 软链。
  nativeBuildInputs = [_7zz];

  unpackPhase = ''
    runHook preUnpack
    7zz x -snld "$src"
    runHook postUnpack
  '';

  installPhase = ''
    runHook preInstall
    # 解出来的 .app 可能在根上,也可能套在以卷名命名的目录里,不写死路径。
    app=$(find . -maxdepth 3 -type d -name 'Kazumi.app' -print -quit)
    if [ -z "$app" ]; then
      echo "Kazumi.app not found in dmg" >&2
      exit 1
    fi
    mkdir -p "$out/Applications"
    cp -R "$app" "$out/Applications/"
    runHook postInstall
  '';

  # 上游二进制带签名,fixup 里的 strip/patch 会把签名弄坏。
  dontFixup = true;

  meta = {
    description = "Rule-based anime scraper and player (macOS release build)";
    homepage = "https://github.com/Predidit/Kazumi";
    license = lib.licenses.gpl3Plus;
    sourceProvenance = [lib.sourceTypes.binaryNativeCode];
    platforms = lib.platforms.darwin;
  };
})
