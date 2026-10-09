{pkgsCross}:
pkgsCross.mingwW64.stdenv.mkDerivation {
  pname = "vfio-d3d-probe";
  version = "1";
  src = ./.;
  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    $CXX -std=c++17 -O2 -Wall -Wextra -static main.cpp -o vfio-d3d-probe.exe \
      -ld3d11 -ld3dcompiler -ldxgi -ldxguid
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    cp vfio-d3d-probe.exe "$out/bin/"
  '';
}
