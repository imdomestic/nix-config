{pkgs}:
let
  mkTest = cross: cross.stdenv.mkDerivation {
    name = "epoll-pwait2-test-${cross.stdenv.hostPlatform.system}";
    dontUnpack = true;
    dontConfigure = true;
    buildInputs = [cross.glibc.static];
    buildPhase = ''
      $CC -std=gnu11 -O2 -Wall -Wextra -Werror -static \
        ${./epoll-pwait2-test.c} -o epoll-test
    '';
    installPhase = ''
      install -Dm755 epoll-test $out/bin/epoll-test
    '';
  };
  native = mkTest pkgs.pkgsCross.aarch64-multiplatform;
  compat = mkTest pkgs.pkgsCross.armv7l-hf-multiplatform;
in {
  inherit native compat;
  initrd = pkgs.makeInitrd {
    contents = [
      {object = "${native}/bin/epoll-test"; symlink = "/init";}
      {object = "${compat}/bin/epoll-test"; symlink = "/test32";}
    ];
  };
  qemu = pkgs.qemu;
}
