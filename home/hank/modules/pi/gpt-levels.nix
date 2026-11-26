# 档位照 pi 内置 openai / google provider 里同名模型的 thinkingLevelMap;fx 也读这一份。
{lib}: let
  codex62 = import ../../../../lib/codex-6.2.nix;
in
  id: {
    off =
      if lib.elem id (["gpt-6.1-sol" "gpt-6-astra"] ++ codex62.ids)
      then null
      else "none";
    minimal = null;
    low = "low";
    medium = "medium";
    high = "high";
    xhigh = "xhigh";
    max =
      if id == "gpt-5.5"
      then null
      else "max";
  }
