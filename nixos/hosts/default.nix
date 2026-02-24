{inputs}: let
  callHost = name: import (./. + "/${name}") {inherit inputs;};
in {
  h610 = callHost "h610";
  b650 = callHost "b650";
  "7540u" = callHost "7540u";
  tank = callHost "tank";
  r5s = callHost "r5s";
  rpi4 = callHost "rpi4";
  wsl = callHost "wsl";
  m3max = callHost "m3max";
  m1pro = callHost "m1pro";
  hackintosh = callHost "hackintosh";
  x86_64-headless = callHost "x86_64-headless";
  "aarch64-headless" = callHost "aarch64-headless";
  n100 = callHost "n100";
  r6s = callHost "r6s";
  aarch64-wsl = callHost "aarch64-wsl";
  shanghai = callHost "shanghai";
  x470 = callHost "x470";
  r2s = callHost "r2s";
  r5sjp = callHost "r5sjp";
  gpd = callHost "gpd";
  m16 = callHost "m16";
}
