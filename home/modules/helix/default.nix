{pkgs, ...}: {
  programs.helix = {
    enable = true;
    package = pkgs.evil-helix;
    settings = {
      theme = "mellow";
      editor.cursor-shape = {
        normal = "block";
        insert = "bar";
        select = "underline";
      };
    };
  };
}
