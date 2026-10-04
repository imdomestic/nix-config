{
  port = 8080;
  context = 32768;
  output = 16384;
  directory = "/var/lib/llm-models/bonsai2";
  models = {
    bonsai-main = {
      name = "Bonsai 2 27B v2 · MTP";
      repository = "BoldingBuilds/Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP-GGUF";
      revision = "e25d197aa62ce0a2f685fc65d76a41b2416c5e66";
      file = "Ternary-Bonsai-2-27B-Abliterated-v2-PQ2_0-MTP.gguf";
      bytes = 7657489696;
      sha256 = "a4e4c7b578131595c1694354bd6c74d00920df1f5082647a6126899753ebebf8";
      mtp = true;
    };
    bonsai-hikari = {
      name = "Hikari Bonsai 2 27B · medium";
      repository = "Hikari07jp/Ternary-Bonsai-2-27B-Abliterated-GGUF";
      revision = "e7f6daf95ab820ef8de7d8f5e883d95d546ab02c";
      file = "Ternary-Bonsai-2-27B-Abliterated-PQ2_0.gguf";
      bytes = 7206168928;
      sha256 = "41a362f422b70a8c2dc74a3cc14447ad0ea702c440f0dbe41dc1796da7b7e342";
      mtp = false;
    };
  };
}
