{
  hosts.hackintosh = {
    system = "x86_64-darwin";
    kind = "darwin";
    roles = ["desktop" "gui"];

    modules = [
      ./system.nix
    ];

    users.hank = {
      tier = "interactive";
      ageKey = "age1xeeg8yu74aqn5x0vzevsuxmsd4nem3cfw2gjwc82ke4mjvep3pxq5p99lh";
    };
  };
}
