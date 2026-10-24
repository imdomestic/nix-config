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

  # No native Mutter monitor option; this generated-config exception is owner-approved.
  environment.etc."xdg/monitors.xml".source = (pkgs.formats.xml {}).generate "268v-monitors.xml" {
    monitors = {
      "@version" = "2";
      configuration = {
        layoutmode = "logical";
        logicalmonitor = {
          x = 0;
          y = 0;
          scale = 2;
          primary = "yes";
          monitor = {
            monitorspec = {
              connector = "eDP-1";
              vendor = "LEN";
              product = "LEN140WQ+";
              serial = "0x00000000";
            };
            mode = {
              width = 2880;
              height = 1800;
              rate = "120.000";
            };
          };
        };
      };
    };
  };

  # Work around the observed cursor-plane atomic commit failures on this panel.
  environment.sessionVariables.MUTTER_DEBUG_DISABLE_HW_CURSORS = "1";
  systemd.services.display-manager.environment.MUTTER_DEBUG_DISABLE_HW_CURSORS = "1";
}
