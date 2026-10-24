{lib, ...}: {
  options.my.nixvim.dev.enable = lib.mkEnableOption ''
    development plugins and language servers (rust, haskell, lean, C/C++,
    python, typst, ...). Off by default so non-dev machines only carry the
    lean editing setup; nix support (nil + core treesitter grammars) is
    always on. Enabled by home/users/<user>/dev.nix.
  '';
}
