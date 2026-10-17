{
  lib,
  stdenv,
  fetchurl,
  kernel,
  kernelModuleMakeFlags,
}:
stdenv.mkDerivation {
  pname = "hid-asus-handshake";
  inherit (kernel) src version;

  patches = [
    (fetchurl {
      url = "https://github.com/torvalds/linux/commit/e82ae34af29e910c96d33c8b3a90c60e27f1625e.patch";
      hash = "sha256-+aaOeide+WOe9JDpOy07xgqVu71Y56lz0Q63/uXJ/IE=";
    })
  ];

  nativeBuildInputs = kernel.moduleBuildDependencies;
  hardeningDisable = ["pic" "format"];
  dontConfigure = true;

  buildPhase = ''
    runHook preBuild
    make -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build \
      ${lib.escapeShellArgs kernelModuleMakeFlags} \
      -j"$NIX_BUILD_CORES" M="$PWD/drivers/hid" hid-asus.ko
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm644 drivers/hid/hid-asus.ko \
      "$out/lib/modules/${kernel.modDirVersion}/updates/hid-asus.ko"
    runHook postInstall
  '';

  meta = {
    description = "ASUS HID keyboard module with the upstream handshake fix";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
  };
}
