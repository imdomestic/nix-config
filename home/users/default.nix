{inputs}: {
  hank = {
    module = import ./hank/default.nix;
  };
  genisys = {
    module = import ./genisys/default.nix;
  };
  fendada = {
    module = import ./fendada/default.nix;
  };
  linwhite = {
    module = import ./linwhite/default.nix;
  };
  nix = {
    module = import ./nix/default.nix;
  };
}
