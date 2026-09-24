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

  patches = [
    ./droidspaces.patch
    ./gunyah-integration.patch
    # HyperOS compatibility and validation: docs/incidents.md#marble-epoll-pwait2.
    ./epoll-pwait2.patch
  ];

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
    # GCC's stdarg.h changes genksyms CRCs; see docs/incidents.md#marble-nix-kernel-headers.
    substituteInPlace Makefile \
      --replace-fail '-isystem $(shell $(CC) -print-file-name=include)' \
        '-isystem $(shell $(CC) -print-resource-dir)/include'
    cp -R ${./gunyah-backport}/drivers/virt/gunyah drivers/virt/
    cp ${./gunyah-backport}/include/linux/gunyah*.h include/linux/
    cp ${./gunyah-backport}/include/uapi/linux/gunyah.h include/uapi/linux/
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
    # LLVM's integrated assembler needs an explicit target on x86_64 builders.
    export CROSS_COMPILE=aarch64-linux-gnu-
    export KBUILD_BUILD_USER=nix
    export KBUILD_BUILD_HOST=nix
    export KBUILD_BUILD_TIMESTAMP="@1772928000"
    # Match the release string used by the currently running marble kernel and
    # its downstream vendor modules.  A mismatch here makes modversions reject
    # otherwise compatible modules before any runtime testing can start.
    export LOCALVERSION=-dirty

    # Determinate's native Linux builder exposes /build over virtiofs. Keep all
    # objects and ThinLTO bitcode on the VM's own tmpfs: lld mmaps its inputs and
    # receives SIGBUS when those inputs live on virtiofs. Buffered output avoids
    # the same problem for the final vmlinux.o write.
    # lld 21's parallel ELF writer can SIGBUS in the 8 GiB native Linux
    # builder during the second kallsyms link. Serialise only the linker;
    # compile jobs still use all builder CPUs.
    export KBUILD_LDFLAGS="--no-mmap-output-file --threads=1"

    make O="$buildDir" gki_defconfig
    # Build vmlinux first so CONFIG_MODVERSIONS produces a complete symbol
    # version dump, then prepare the module linker script.  This 5.10 tree
    # names the vmlinux-only dump vmlinux.symvers, while an M= build expects
    # the conventional Module.symvers name.
    make O="$buildDir" -j$NIX_BUILD_CORES Image
    make O="$buildDir" -j$NIX_BUILD_CORES modules_prepare
    cp "$buildDir/vmlinux.symvers" "$buildDir/Module.symvers"
    make O="$buildDir" -j$NIX_BUILD_CORES M=drivers/virt/gunyah modules

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
    for option in \
      CONFIG_GUNYAH \
      CONFIG_GUNYAH_VCPU \
      CONFIG_GUNYAH_IRQFD \
      CONFIG_GUNYAH_IOEVENTFD; do
      grep -qx "$option=m" "$buildDir/.config"
    done
    test -s "$buildDir/arch/arm64/boot/Image"
    for symbol in __arm64_sys_epoll_pwait2 __arm64_compat_sys_epoll_pwait2; do
      grep -Eq " [Tt] $symbol$" "$buildDir/System.map"
    done
    # These vendor imports catch accidental use of the host GCC's va_list typedef.
    grep -Eq '^0x00148653[[:space:]]+vsnprintf[[:space:]]' "$buildDir/vmlinux.symvers"
    grep -Eq '^0xaa0c318b[[:space:]]+vscnprintf[[:space:]]' "$buildDir/vmlinux.symvers"
    for module in gunyah gunyah_vcpu gunyah_irqfd gunyah_ioeventfd; do
      test -s "$buildDir/drivers/virt/gunyah/$module.ko"
    done

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    buildDir=/tmp/templar-kernel-build
    install -Dm444 "$buildDir/arch/arm64/boot/Image" $out/Image
    install -Dm444 "$buildDir/.config" $out/config
    install -Dm444 "$buildDir/System.map" $out/System.map
    install -Dm444 "$buildDir/vmlinux.symvers" $out/Module.symvers
    for module in gunyah gunyah_vcpu gunyah_irqfd gunyah_ioeventfd; do
      install -Dm444 "$buildDir/drivers/virt/gunyah/$module.ko" \
        "$out/modules/$module.ko"
    done

    mkdir -p $out/nix-support
    cat >$out/nix-support/build-info <<EOF
    source-revision=012918fa5fda0f62c4db9660da425acf3c746486
    compiler=$(${llvmPackages.clang}/bin/clang --version | head -n1)
    kernel-release=$(make -s O="$buildDir" kernelrelease)
    epoll-pwait2=upstream-backport-arm64-and-compat
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
