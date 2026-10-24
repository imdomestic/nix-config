let
  gpuIDs = [
    "1002:67ef"
    "1002:aae0"
  ];
in
  {
    pkgs,
    lib,
    ...
  }: {
    boot.kernelParams =
      [
        "intel_iommu=on"
      ]
      ++ [("vfio_pci.ids=" + lib.concatStringsSep "," gpuIDs)];
    boot.kernelModules = [
      "vfio_virqfd"
      "vfio_pci"
      "vfio_iommu_type1"
      "vfio"
    ];
  }
