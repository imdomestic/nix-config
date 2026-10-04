let
  flake = builtins.getFlake (toString ../.);
  pkgs = flake.nixosConfigurations.ms7e56.pkgs;
  engine = pkgs.callPackage ../pkgs/llama-cpp-prism {};
  gguf = pkgs.python3Packages.gguf.overridePythonAttrs (old: {
    version = "0.19.0";
    src = engine.src;
    meta = old.meta // {changelog = "https://github.com/PrismML-Eng/llama.cpp/commit/adfffbe41b2cabcd51fff326ab045662265062bb";};
  });
in
  pkgs.python3.withPackages (ps: [ps.httpx ps.httpx-sse ps.jsonschema ps.jinja2 gguf])
