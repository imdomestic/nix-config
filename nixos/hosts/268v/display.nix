{pkgs, ...}: let
  panelEdid = pkgs.runCommand "268v-panel-edid" {} ''
    install -Dm444 ${./len8ac3-edid.bin} "$out/lib/firmware/edid/len8ac3.bin"
  '';
in {
  # The panel AUX read returns an extension block as its header; see docs/incidents.md#268v-display-edid.
  hardware.display = {
    edid.packages = [panelEdid];
    outputs."eDP-1".edid = "len8ac3.bin";
  };
  boot.initrd.extraFirmwarePaths = ["edid/len8ac3.bin"];

  # Work around the observed cursor-plane atomic commit failures on this panel.
  environment.sessionVariables.MUTTER_DEBUG_DISABLE_HW_CURSORS = "1";
  systemd.services.display-manager.environment.MUTTER_DEBUG_DISABLE_HW_CURSORS = "1";
}
