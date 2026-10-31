{
  enabled = true;
  auto_update = false;
  language = "zh";
  historian.pi = {
    model = "cliproxy/gpt-5.5";
    thinking_level = "low";
  };
  dreamer.disable = true;
  embedding = {
    provider = "local";
    model = "Xenova/paraphrase-multilingual-MiniLM-L12-v2";
    local_dtype = "q8";
  };
}
