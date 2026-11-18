let
  levels = ["low" "medium" "high" "xhigh" "max"];
  ids = ["gpt-6.2-sol" "gpt-6.2-astra"];
  models = {
    "gpt-6.2-sol" = {
      name = "GPT 6.2 Sol";
      context = 500000;
      input = 372000;
      output = 128000;
      maxContext = 872000;
    };
    "gpt-6.2-astra" = {
      name = "GPT 6.2 Astra";
      context = 272000;
      input = 144000;
      output = 128000;
      maxContext = 872000;
    };
  };
in {
  inherit levels ids models;
  # Codex account discovery defaults, not the public API's 1.05M limit; docs/cliproxy-model-catalog.md.
  catalog =
    map (id: {
      inherit id;
      object = "model";
      created = 1794942000;
      owned_by = "openai";
      type = "openai";
      version = "gpt-6.2";
      display_name = models.${id}.name;
      context_length = models.${id}.context;
      max_completion_tokens = models.${id}.output;
      supported_parameters = ["tools"];
      thinking.levels = levels;
      supportedInputModalities = ["text" "image"];
      supportedOutputModalities = ["text"];
    })
    ids;
}
