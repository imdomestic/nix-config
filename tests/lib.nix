# Plumbing for the fleet's VM tests: boot a host's real module list in a NixOS
# test VM, and snapshot what it exposes with fleet-probe. Why the tests look
# like this: docs/decisions.md#fleet-tests.
{
  pkgs,
  lib,
  systemModules,
  nixos,
}: let
  agePub = lib.fileContents ./secrets/age.pub;

  # The host's sops secrets, re-encrypted to the test-only key in
  # ./secrets/age.key with placeholder values (or the ones given), so the
  # units that read them can start. Names come from the host's own
  # evaluation; nested names ("a/b") become nested YAML, as sops-nix reads them.
  testSecrets = hostName: values: let
    names = lib.attrNames (nixos.${hostName}.config.sops.secrets or {});
    tree =
      lib.foldl' lib.recursiveUpdate {}
      (map (n: lib.setAttrByPath (lib.splitString "/" n) (values.${n} or "fleet-test-${n}")) names);
  in {
    inherit names;
    file = pkgs.runCommand "fleet-test-secrets-${hostName}.yaml" {nativeBuildInputs = [pkgs.sops];} ''
      sops --encrypt --age ${agePub} --input-type json --output-type yaml \
        ${pkgs.writeText "plain.json" (builtins.toJSON tree)} > $out
    '';
  };

  # What has to change for a host's modules to boot in a VM. qemu-vm.nix
  # already replaces file systems, swap and the boot loader.
  vmify = {
    hostName,
    system,
    secrets,
  }: {lib, ...}: {
    nixpkgs.hostPlatform = lib.mkDefault system;
    # The test framework names the machine after its node; keep the real name.
    networking.hostName = lib.mkVMOverride hostName;
    # No GPU in the VM: the nvidia driver and its toolkit would only fail.
    services.xserver.videoDrivers = lib.mkVMOverride ["modesetting"];
    hardware.nvidia-container-toolkit.enable = lib.mkVMOverride false;
    sops = {
      validateSopsFiles = lib.mkVMOverride false;
      defaultSopsFile = lib.mkVMOverride secrets.file;
      # sops-nix refuses a key in the store; copy it out before it decrypts.
      age.keyFile = lib.mkVMOverride "/var/lib/fleet-test/age.key";
      age.sshKeyPaths = lib.mkVMOverride [];
      gnupg.sshKeyPaths = lib.mkVMOverride [];
      secrets = lib.genAttrs secrets.names (n: {
        sopsFile = lib.mkVMOverride secrets.file;
        format = lib.mkVMOverride "yaml";
        key = lib.mkVMOverride n;
      });
    };
    system.activationScripts.fleetTestAgeKey.text = "install -Dm400 ${./secrets/age.key} /var/lib/fleet-test/age.key";
    system.activationScripts.setupSecrets.deps = ["fleetTestAgeKey"];
    # The host's NICs do not exist here; waiting for them only delays boot.
    systemd.network.wait-online.enable = lib.mkVMOverride false;
  };

  probe = pkgs.writeShellApplication {
    name = "fleet-probe";
    runtimeInputs = with pkgs; [jq iproute2 nftables iptables systemd procps gnused gawk gnugrep coreutils bpftools nix];
    text = builtins.readFile ./fleet-probe.sh;
  };

  # Units that fail in any VM because it never joins the tailnet.
  offTailnet = {
    "rex-login-server.service" = "binds to the host's tailnet addresses";
  };

  # Boot the host's real configuration, take a snapshot into $out/probe.json,
  # and fail on any unit that failed or is in a restart loop and is not listed
  # with a reason.
  smoke = {
    hostName,
    allowedFailures ? {},
    memory ? 4096,
  }: let
    allowed = offTailnet // allowedFailures;
    sm = systemModules {
      inherit hostName;
      withHardware = false;
    };
  in
    pkgs.testers.runNixOSTest {
      name = "smoke-${hostName}";
      node.specialArgs = sm.specialArgs;
      # The host's modules set nixpkgs.config and overlays; let them build
      # their own pkgs, as they do outside the test.
      node.pkgsReadOnly = false;
      nodes.machine = {
        imports =
          sm.modules
          ++ [
            (vmify {
              inherit hostName;
              inherit (nixos.${hostName}.pkgs.stdenv.hostPlatform) system;
              secrets = testSecrets hostName {};
            })
          ];
        virtualisation = {
          memorySize = memory;
          cores = 4;
          diskSize = 8192;
        };
      };
      testScript = ''
        import json
        machine.wait_for_unit("multi-user.target")
        # Oneshots and timers triggered at boot settle first.
        machine.sleep(30)
        machine.succeed("${probe}/bin/fleet-probe > /tmp/probe.json")
        machine.copy_from_vm("/tmp/probe.json", "")
        snap = json.loads(machine.succeed("cat /tmp/probe.json"))
        allowed = set(json.loads('${builtins.toJSON (lib.attrNames allowed)}'))
        unexpected = sorted((set(snap["failed"]) | set(snap["restarting"])) - allowed)
        assert not unexpected, f"units failed or restarting: {unexpected}"
      '';
    };
in {
  inherit testSecrets vmify probe smoke;
}
