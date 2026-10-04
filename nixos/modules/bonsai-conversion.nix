{...}: {
  # 完整词嵌入的独立解码校验需要超过 32 GiB 主机内存。
  swapDevices = [
    {
      device = "/var/lib/bonsai-ninfer/convert.swap";
      size = 65536;
    }
  ];
  systemd.tmpfiles.rules = ["d /var/lib/bonsai-ninfer 0755 root root -"];
}
