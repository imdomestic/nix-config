{
  pkgs,
  extraModels,
}: let
  # Custom sources replace every provider; snapshot upkeep: docs/cliproxy-model-catalog.md.
  baseline = builtins.fromJSON (builtins.readFile (builtins.fetchurl {
    url = "https://raw.githubusercontent.com/router-for-me/models/11a1417210520dc526aacdd4bde9303398ecfd4d/models.json";
    sha256 = "487476de10655f562955630463503f15ba3990837818344ac8aa40acafc918cc";
  }));
  extendSection = section: additions: let
    original = baseline.${section} or [];
    ids = map (model: model.id) additions;
    extendModel = model: let
      previous = builtins.filter (entry: entry.id == model.id) original;
    in
      (
        if previous == []
        then {}
        else builtins.head previous
      )
      // model;
  in
    builtins.filter (model: !(builtins.elem model.id ids)) original
    ++ map extendModel additions;
  catalog = baseline // builtins.mapAttrs extendSection extraModels;
in
  (pkgs.formats.json {}).generate "cliproxy-model-catalog.json" catalog
