{ inputs }:
let
  callHost = name: import (./. + "/${name}") { inherit inputs; };
in {
  H610 = callHost "H610";
  b650 = callHost "b650";
  "7540u" = callHost "7540u";
  tank = callHost "tank";
  r5s = callHost "r5s";
  rpi4 = callHost "rpi4";
  wsl = callHost "wsl";
  m3max = callHost "m3max";
  hackintosh = callHost "hackintosh";
  x86_64-headless = callHost "x86_64-headless";
  "aarch64-headless" = callHost "aarch64-headless";
  n100 = callHost "n100";
  r6s = callHost "r6s";
  aarch64-wsl = callHost "aarch64-wsl";
}
