{
  inputs,
  lib,
  ...
}: {
  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
    settings = lib.importTOML "${inputs.zsh-linwhite}/starship.toml";
  };
}
