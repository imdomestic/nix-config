{lib, ...}: {
  options.my.pi.providers = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    description = "Extra providers merged into ~/.pi/agent/models.json.";
  };
}
