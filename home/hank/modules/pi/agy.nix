{
  config,
  lib,
  pkgs,
  ...
}: let
  placement = config.my.fleet.placements.agy-proxy;
in {
  sops.secrets."agy-proxy/api_key".sopsFile = ../../../../secrets/clients/agy-proxy.yaml;

  my.pi.providers.agy = {
    name = "agy";
    baseUrl = "https://${placement.tsName}/agy/v1beta";
    api = "google-generative-ai";
    # Runtime proxy key only, never the Google OAuth state; docs/agy-proxy.md.
    apiKey = "!${pkgs.coreutils}/bin/cat ${lib.escapeShellArg config.sops.secrets."agy-proxy/api_key".path}";
    models = import ./agy-models.nix {inherit lib;};
  };

  my.pi.providers.agy-completions = {
    name = "agy-completions";
    baseUrl = "https://${placement.tsName}/agy/v1";
    api = "openai-completions";
    apiKey = config.my.pi.providers.agy.apiKey;
    models = map (model:
      model
      // {
        name = "agy-completions/${model.id}";
        compat = {
          supportsDeveloperRole = false;
          supportsReasoningEffort = true;
          thinkingFormat = "openai";
        };
      })
    config.my.pi.providers.agy.models;
  };
}
