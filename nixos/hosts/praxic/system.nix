{...}: {
  imports = [../../../darwin/profiles/hank-workstation.nix];

  networking.wg-quick.interfaces.wg0 = {
    # 迁移并核验密钥后再启用，见 docs/mac-migration.md#network-identity。
    autostart = false;
    address = ["10.0.0.65/24"];
    listenPort = 50722;
    privateKeyFile = "/Users/hank/Documents/privatekey";
    peers = [
      {
        publicKey = "i9ZU3WdqNxUyqtaM9F8Rbrs4ophdNpQ6wZeO/bV/jjQ=";
        presharedKeyFile = "/Users/hank/Documents/presharedkey";
        allowedIPs = ["10.0.0.0/24"];
        endpoint = "sh.imdomestic.com:50722";
        persistentKeepalive = 25;
      }
    ];
  };
}
