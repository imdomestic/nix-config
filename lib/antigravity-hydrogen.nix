let
  context = 1048576;
  output = 262144;
  variants = [
    {
      level = "low";
      label = "Low";
    }
    {
      level = "medium";
      label = "Medium";
    }
    {
      level = "high";
      label = "High";
    }
    {
      level = "xhigh";
      label = "XHigh";
    }
  ];
  models =
    map (variant: {
      id = "gemini-4-hydrogen-${variant.level}";
      name = "Gemini 4 Hydrogen (${variant.label})";
      inherit (variant) level;
    })
    variants;
in {
  inherit context output models;
  ids = map (model: model.id) models;
  # These are distinct Google presets, not aliases of XHigh; docs/incidents.md#antigravity-hydrogen-effort.
  catalog =
    map (model: {
      inherit (model) id;
      object = "model";
      owned_by = "antigravity";
      type = "antigravity";
      name = model.id;
      display_name = model.name;
      description = model.name;
      context_length = context;
      max_completion_tokens = output;
      thinking.levels = [model.level];
      supportedInputModalities = ["text" "image" "audio" "video"];
      supportedOutputModalities = ["text"];
    })
    models;
}
