{
  lib,
  pkgs,
  ...
}: let
  manifestsDirectory = "/var/lib/rancher/k3s/server/manifests";
  packagedManifests = [
    "aggregated-metrics-reader"
    "auth-delegator"
    "auth-reader"
    "metrics-apiservice"
    "metrics-server-deployment"
    "metrics-server-service"
    "resource-reader"
  ];
in {
  systemd.services.k3s.preStart = lib.mkAfter ''
    ${pkgs.coreutils}/bin/install -d -m 0755 ${manifestsDirectory}/metrics-server
    ${lib.concatMapStringsSep "\n" (name: ''
        ${pkgs.coreutils}/bin/touch ${manifestsDirectory}/metrics-server/${name}.yaml.skip
      '')
      packagedManifests}
    ${pkgs.coreutils}/bin/install -m 0644 ${./manifests/vex-metrics-server.yaml} ${manifestsDirectory}/vex-metrics-server.yaml
  '';
}
