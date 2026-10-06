{inputs}: let
  callHost = name: import (./. + "/${name}") {inherit inputs;};
in {
  h610 = callHost "h610";
  h310 = callHost "h310";
  taipan = callHost "taipan";
  "268v" = callHost "268v";
  tank = callHost "tank";
  r5s = callHost "r5s";
  rpi4 = callHost "rpi4";
  wsl = callHost "wsl";
  praxic = callHost "praxic";
  aegis = callHost "aegis";
  alex = callHost "alex";
  hackintosh = callHost "hackintosh";
  macbook-pro-3 = callHost "macbook-pro-3";
  x86_64-headless = callHost "x86_64-headless";
  "aarch64-headless" = callHost "aarch64-headless";
  r6s = callHost "r6s";
  aarch64-wsl = callHost "aarch64-wsl";
  tokyo = callHost "tokyo";
  x470 = callHost "x470";
  r2s = callHost "r2s";
  gizmo = callHost "gizmo";
  gpd = callHost "gpd";
  encore = callHost "encore";
  "9950x" = callHost "9950x";
  seraph = callHost "seraph";
  marble = callHost "marble";
  cse = callHost "cse";
}
