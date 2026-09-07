{inputs, pkgs}:
import (inputs.qq-bot + "/nix/ops-compat-package.nix") {
  inherit pkgs;
  package = inputs.maxops.packages.${pkgs.stdenv.hostPlatform.system}.default;
}
