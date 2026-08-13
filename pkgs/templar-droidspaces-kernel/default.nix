{
  lib,
  stdenv,
  fetchurl,
  bc,
  bison,
  cpio,
  elfutils,
  flex,
  gawk,
  llvmPackages,
  openssl,
  pahole,
  perl,
  pkg-config,
  python3,
  rsync,
}:
stdenv.mkDerivation {
  pname = "templar-droidspaces-kernel";
  version = "5.10.252-unstable-2026-03-08";

  # Keep the archive packed until the Linux build starts. This repository has
  # case-distinct netfilter files (for example xt_MARK.h and xt_mark.h), which
  # fetchFromGitHub's unpacked fixed-output derivation collapses on Darwin.
  src = fetchurl {
    url = "https://github.com/Steambot12/Templar-Kernel-GKI-5.10/archive/012918fa5fda0f62c4db9660da425acf3c746486.tar.gz";
    hash = "sha256-1Sf3XhIDMx18wF/DyYMTcy0AC07N82Gpc04kL1d2wms=";
  };

  patches = [./droidspaces.patch];

  nativeBuildInputs = [
    bc
    bison
    cpio
    elfutils
    flex
    gawk
    llvmPackages.clang
    llvmPackages.lld
    llvmPackages.llvm
    pahole
    perl
    pkg-config
    python3
    rsync
  ];

  buildInputs = [openssl];

  # Kernel build flags are intentionally managed by Kbuild, not by the host
  # stdenv. In particular, stack-protector hardening for host executables must
  # not leak into the freestanding arm64 image.
  hardeningDisable = ["all"];

  postPatch = ''
    patchShebangs scripts
  '';

  enableParallelBuilding = true;

  buildPhase = ''
    runHook preBuild

    buildDir=/tmp/templar-kernel-build
    mkdir -p "$buildDir"

    export ARCH=arm64
    export LLVM=1
    export LLVM_IAS=1
    export KBUILD_BUILD_USER=nix
    export KBUILD_BUILD_HOST=nix
    export KBUILD_BUILD_TIMESTAMP="@1772928000"

    # Determinate's native Linux builder exposes /build over virtiofs. Keep all
    # objects and ThinLTO bitcode on the VM's own tmpfs: lld mmaps its inputs and
    # receives SIGBUS when those inputs live on virtiofs. Buffered output avoids
    # the same problem for the final vmlinux.o write.
    export KBUILD_LDFLAGS="--no-mmap-output-file"

    make O="$buildDir" gki_defconfig
    make O="$buildDir" -j$NIX_BUILD_CORES Image

    for option in \
      CONFIG_SYSVIPC \
      CONFIG_POSIX_MQUEUE \
      CONFIG_UTS_NS \
      CONFIG_IPC_NS \
      CONFIG_USER_NS \
      CONFIG_PID_NS \
      CONFIG_NET_NS \
      CONFIG_DEVTMPFS \
      CONFIG_TMPFS_POSIX_ACL \
      CONFIG_TMPFS_XATTR \
      CONFIG_LTO_CLANG_THIN; do
      grep -qx "$option=y" "$buildDir/.config"
    done
    grep -qx '# CONFIG_LTO_CLANG_FULL is not set' "$buildDir/.config"
    test -s "$buildDir/arch/arm64/boot/Image"

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    buildDir=/tmp/templar-kernel-build
    install -Dm444 "$buildDir/arch/arm64/boot/Image" $out/Image
    install -Dm444 "$buildDir/.config" $out/config

    mkdir -p $out/nix-support
    cat >$out/nix-support/build-info <<EOF
    source-revision=012918fa5fda0f62c4db9660da425acf3c746486
    compiler=$(${llvmPackages.clang}/bin/clang --version | head -n1)
    kernel-release=$(make -s O="$buildDir" kernelrelease)
    EOF

    runHook postInstall
  '';

  meta = {
    description = "Templar Android GKI 5.10 kernel with namespaces required by Droidspaces";
    homepage = "https://github.com/Steambot12/Templar-Kernel-GKI-5.10";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
  };
}
