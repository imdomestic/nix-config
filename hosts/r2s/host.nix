{
  hosts.r2s = {
    system = "aarch64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["server" "router"];
    tsName = "r2s.inner.imdomestic.com";
    ageKey = "age1gf9jpsr9zr2myn780m8emtk5qzfz87jqdlrju744cvmj3v02nqpsdkkueh";
    lanRoutes = ["192.168.4.0/24"];
    maxTier = "interactive";
    buildOn = "r6s";

    users.hank = {};
  };
}
