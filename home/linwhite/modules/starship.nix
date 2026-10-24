{
  config,
  inputs,
  lib,
  ...
}: {
  home.sessionVariables.starship_config = config.programs.starship.configPath;

  programs.starship = {
    enable = true;
    enableTransience = true;
    enableZshIntegration = true;
    settings = lib.importTOML "${inputs.zsh-linwhite}/starship.toml";
  };
}
