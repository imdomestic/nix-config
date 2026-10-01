{
  config,
  lib,
  pkgs,
  ...
}: let
  # The pinned nixpkgs package predates upstream's GNOME 50 compatibility fixes.
  forge = pkgs.gnomeExtensions.forge.overrideAttrs (oldAttrs: {
    version = "50-unstable-46736af";
    src = pkgs.fetchFromGitHub {
      owner = "forge-ext";
      repo = "forge";
      rev = "46736af63815b46cadeb1db2988f04d60e6601b8";
      hash = "sha256-bdoD5k33l0SwwuEmd+EvB0FiVJdbtIMeBrUAjRhSg2s=";
    };
    patches =
      (oldAttrs.patches or [])
      ++ [
        ./writable-stylesheet.patch
        ./keyboard-resize-boundary.patch
      ];
  });
  floatingSettingsRule = builtins.toJSON {
    wmClass = "org.gnome.Settings";
    mode = "float";
  };
  # Forge has no dconf rule list; this mutable-config exception is owner-approved.
  updateFloatingRules = pkgs.writeShellApplication {
    name = "forge-floating-settings";
    runtimeInputs = [pkgs.coreutils pkgs.jq];
    text = ''
      rules="$1"
      source="$rules"
      if [[ ! -f "$source" ]]; then
        source="${forge}/share/gnome-shell/extensions/forge@jmmaranan.com/config/windows.json"
      fi
      mkdir -p "$(dirname "$rules")"
      temporary=$(mktemp "''${rules}.XXXXXX")
      trap 'rm -f "$temporary"' EXIT
      jq --argjson rule ${lib.escapeShellArg floatingSettingsRule} '
        .overrides = ([.overrides[] | select(
          (.wmClass == $rule.wmClass and .wmTitle == null and .wmId == null) | not
        )] + [$rule])
      ' "$source" > "$temporary"
      if cmp -s "$rules" "$temporary"; then
        exit 0
      fi
      mv "$temporary" "$rules"
      if [[ -n "''${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
        ${pkgs.glib}/bin/gsettings \
          --schemadir ${forge}/share/gnome-shell/extensions/forge@jmmaranan.com/schemas \
          set org.gnome.shell.extensions.forge window-overrides-reload-trigger \
          "$(date +%s)" || true
      fi
    '';
  };
in {
  programs.gnome-shell = {
    enable = true;
    extensions = [{package = forge;}];
  };
  dconf.settings."org/gnome/shell/extensions/forge".tiling-mode-enabled = true;
  home.activation.forgeFloatingSettings = lib.hm.dag.entryAfter ["writeBoundary"] ''
    run ${lib.getExe updateFloatingRules} ${lib.escapeShellArg "${config.xdg.configHome}/forge/config/windows.json"}
  '';
}
