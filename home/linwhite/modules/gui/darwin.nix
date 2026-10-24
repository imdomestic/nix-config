{
  config,
  lib,
  ...
}: {
  imports = [./common.nix];

  # 旧 nix-darwin 的用户 agent 不会自动清理，见 docs/incidents.md#aerospace-legacy-agent。
  home.activation.removeLegacyAerospace =
    lib.mkIf (config.programs.aerospace.enable && config.programs.aerospace.launchd.enable)
    (lib.hm.dag.entryBetween ["linkGeneration" "setupLaunchAgents"] ["writeBoundary"] ''
      legacyAerospaceAgent=${lib.escapeShellArg "${config.home.homeDirectory}/Library/LaunchAgents/org.nixos.aerospace.plist"}
      legacyAerospaceService="gui/$(id -u)/org.nixos.aerospace"
      if /bin/launchctl print "$legacyAerospaceService" >/dev/null 2>&1; then
        run /bin/launchctl bootout --wait "$legacyAerospaceService"
      fi
      if [[ -e "$legacyAerospaceAgent" || -L "$legacyAerospaceAgent" ]]; then
        run rm -f -- "$legacyAerospaceAgent"
      fi
    '');
}
