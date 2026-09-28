{lib, ...}: {
  options.my.nixvim.tabline.underline.enable = lib.mkEnableOption ''
    the second-row underline below Hank's buffer tabs
  '';

  options.my.nixvim.tabline.animation.enable =
    lib.mkEnableOption ''
      the underline gliding between tabs instead of jumping
    ''
    // {default = true;};

  options.my.nixvim.tabline.project.enable = lib.mkEnableOption ''
    the fixed project-name label at the left end of Hank's tabline
  '';

  options.my.nixvim.dev.enable = lib.mkEnableOption ''
    development plugins and language servers (rust, haskell, lean, C/C++,
    python, typst, ...). Off by default so non-dev machines only carry the
    lean editing setup; nix support (nil + core treesitter grammars) is
    always on. Enabled by home/users/<user>/dev.nix.
  '';
}
