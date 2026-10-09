{
  stdenv,
  pkg-config,
  libinput,
  libevdev,
}:
stdenv.mkDerivation {
  pname = "vfio-touchpad";
  version = "1";
  src = ./.;
  nativeBuildInputs = [pkg-config];
  buildInputs = [libinput libevdev];
  dontConfigure = true;
  buildPhase = ''
    runHook preBuild
    $CC -std=c11 -O2 -Wall -Wextra -Werror main.c -o vfio-touchpad \
      $(pkg-config --cflags --libs libinput libevdev)
    runHook postBuild
  '';
  installPhase = ''
    mkdir -p "$out/bin"
    cp vfio-touchpad "$out/bin/"
  '';
}
