{
  lib,
  vimUtils,
}:
vimUtils.buildVimPlugin {
  pname = "hank-tabline";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = ./lua;
  };
}
