{
  config,
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
  assertions = [
    {
      assertion = config.services.k3s.package.version == "1.35.8+k3s1";
      message = "Vex metrics-server manifests require k3s 1.35.8+k3s1";
    }
  ];

  systemd.services.k3s.preStart = lib.mkAfter ''
    ${pkgs.coreutils}/bin/install -d -m 0755 ${manifestsDirectory}/metrics-server
    ${lib.concatMapStringsSep "\n" (name: ''
      ${pkgs.coreutils}/bin/touch ${manifestsDirectory}/metrics-server/${name}.yaml.skip
    '') packagedManifests}
    ${pkgs.coreutils}/bin/install -m 0644 ${./manifests/vex-metrics-server.yaml} ${manifestsDirectory}/vex-metrics-server.yaml
  '';
}
