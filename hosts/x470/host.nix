_: {
  hosts.x470 = {
    system = "x86_64-linux";
    kind = "nixos";
    inChina = true;
    roles = ["desktop" "gui" "server"];
    sshUser = "root";

    users.hank = {};
  };
}
