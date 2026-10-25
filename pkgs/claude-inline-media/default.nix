{
  lib,
  stdenvNoCC,
  nodejs,
  pi-math,
}:
# A Claude Code mod: math and pictures drawn in the transcript
# (docs/claude-code-mods.md#inline-media). The output is the plugin folder.
stdenvNoCC.mkDerivation {
  pname = "claude-inline-media";
  inherit (lib.importJSON ./mod/.claude-plugin/plugin.json) version;

  src = ./mod;

  # For patchShebangs: render.mjs's `#!/usr/bin/env node` becomes this node.
  buildInputs = [nodejs];

  installPhase = ''
    runHook preInstall
    cp -r . "$out"
    # render.mjs takes MathJax and resvg from the node_modules beside it.
    ln -s ${pi-math}/node_modules "$out/render/node_modules"
    runHook postInstall
  '';

  meta = {
    description = "Claude Code mod drawing LaTeX and pictures in the terminal transcript";
    inherit (pi-math.meta) platforms;
  };
}
