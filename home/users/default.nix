{inputs}: {
  hank = {
    module = import ./hank/default.nix;
    dev = import ./hank/dev.nix;
  };
  genisys = {
    module = import ./genisys/default.nix;
  };
  fendada = {
    module = import ./fendada/default.nix;
  };
  linwhite = {
    module = import ./linwhite/default.nix;
    dev = import ./linwhite/dev.nix;
  };
  nix = {
    module = import ./nix/default.nix;
  };
}
