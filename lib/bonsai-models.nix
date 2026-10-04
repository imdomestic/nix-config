{
  port = 8080;
  context = 174080;
  output = 16384;
  directory = "/var/lib/bonsai-ninfer";
  image = "localhost/ninfer:bonsai-9c875f71-sm120a-high";
  imageArchive = "ninfer-bonsai-9c875f71-sm120a-high.oci";
  models = {
    bonsai-main = {
      name = "Bonsai 2 27B v2 · NInfer MTP";
      file = "bonsai-main-e25d197aa62ce0a2.ninfer";
      sha256 = "244e513ab2809e70d6cb1446ef61e20082bcda51ae3ab3def7c2a7542e47b00f";
      bytes = 10533732876;
      port = 8100;
      draftTokens = 3;
      reasoningEffort = "high";
    };
    bonsai-hikari = {
      name = "Hikari Bonsai 2 27B · NInfer MTP medium";
      file = "bonsai-hikari-e7f6daf95ab820ef.ninfer";
      sha256 = "3674e71fc9016550df976c7a33460e95bcfe8bbfafe80682bce36012e15f4794";
      bytes = 10533732876;
      port = 8101;
      draftTokens = 3;
      reasoningEffort = "medium";
    };
  };
}
