{
  lib,
  fetchurl,
  runCommand,
  innoextract,
  ripgrep,
  zip,
}: let
  src = fetchurl {
    url = "https://download.lenovo.com/consumer/mobiles/xqy7067fvs1jttg0.exe";
    sha256 = "c6bdda995aad3d80a590cf1029bb4e7b23542566c85f98a4d1656f143a647418";
  };
in
  runCommand "268v-windows-oem-driver-32.0.101.7026" {
    nativeBuildInputs = [innoextract ripgrep zip];
    meta = {
      description = "Signed Lenovo 83JX Intel graphics driver for the Windows VFIO comparison";
      homepage = "https://support.lenovo.com/us/en/downloads/ds573068";
      license = lib.licenses.unfree;
      platforms = ["x86_64-linux"];
    };
  } ''
    innoextract --extract --output-dir unpacked ${src}
    mkdir -p "$out"
    cd 'unpacked/code$GetExtractPath$'
    rg --encoding utf-16le -Fq 'DriverVer=08/19/2025,32.0.101.7026' Graphics/iigd_dch.inf
    rg --encoding utf-16le -Fq 'PCI\VEN_8086&DEV_64A0&SUBSYS_383E17AA' Graphics/iigd_dch.inf
    zip -q -r -1 "$out/LenovoGraphics.zip" Graphics
  ''
