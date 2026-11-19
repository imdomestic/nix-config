{lib}: let
  pricing = import ./pricing.nix;
  hydrogen = import ../../../../lib/antigravity-hydrogen.nix;
  levels = ["off" "minimal" "low" "medium" "high" "xhigh" "max"];
  fixedLevel = selected:
    lib.genAttrs levels (level:
      if level == selected
      then level
      else null);
  flashLevels = {
    off = null;
    minimal = "minimal";
    low = "low";
    medium = "medium";
    high = "high";
    xhigh = null;
    max = null;
  };
  model = id: output: thinkingLevelMap: {
    inherit id thinkingLevelMap;
    name = "agy/${id}";
    reasoning = true;
    input = ["text" "image"];
    contextWindow = 1048576;
    maxTokens = output;
    cost = pricing.${id};
  };
in
  [
    (model "gemini-3-flash" 65536 flashLevels)
    (model "gemini-3.1-flash-lite" 65535 flashLevels)
    (model "gemini-3.5-flash-lite" 65535 flashLevels)
    (model "gemini-3.8-flash-high" 65536 (fixedLevel "high"))
  ]
  # Distinct presets, not effort aliases; docs/incidents.md#antigravity-hydrogen-effort.
  ++ map (preset:
    (model preset.id 65536 (fixedLevel preset.level))
    # Pi 1.5.2's Google adapter rejects XHIGH; the scoped adapter retains native semantics.
    // lib.optionalAttrs (preset.level == "xhigh") {api = "agy-google-xhigh";})
  hydrogen.models
