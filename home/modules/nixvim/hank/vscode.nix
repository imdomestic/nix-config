{lib, ...}: let
  action = key: command: desc: {
    inherit key;
    mode = "n";
    action = lib.nixvim.mkRaw ''function() require("vscode").action("${command}") end'';
    options = {
      silent = true;
      inherit desc;
    };
  };
in {
  imports = [./editing.nix];

  # A separate wrapped init prevents the terminal UI/LSP setup from loading.
  wrapRc = true;
  impureRtp = false;
  withRuby = false;
  withPython3 = false;
  withNodeJs = false;
  performance.byteCompileLua.enable = true;

  plugins.treesitter = {
    highlight.enable = false;
    indent.enable = false;
    folding.enable = false;
  };

  keymaps = [
    (action "<leader>ff" "workbench.action.quickOpen" "Find files")
    (action "<leader>f<space>" "workbench.action.quickOpen" "Find files and recent files")
    (action "<leader>fr" "workbench.action.quickOpen" "Recent files")
    (action "<leader>fb" "workbench.action.showAllEditors" "Open editors")
    (action "<leader>fw" "workbench.action.findInFiles" "Search in files")
    (action "<leader>fs" "workbench.action.showAllSymbols" "Workspace symbols")
    (action "<leader>fk" "workbench.action.openGlobalKeybindings" "Keyboard shortcuts")
    (action "<leader>e" "workbench.view.explorer" "Explorer")
    (action "<leader>g" "workbench.view.scm" "Source control")
    (action "<leader>lD" "workbench.actions.view.problems" "Diagnostics")

    (action "[b" "workbench.action.previousEditorInGroup" "Previous editor")
    (action "]b" "workbench.action.nextEditorInGroup" "Next editor")
    (action "<leader>c" "workbench.action.closeActiveEditor" "Close editor")
    (action "<leader>q" "workbench.action.closeActiveEditor" "Close editor")
    (action "<leader>Q" "workbench.action.closeAllEditors" "Close all editors (prompt for unsaved changes)")
    (action "<leader>w" "workbench.action.files.save" "Save")
    (action "<C-h>" "workbench.action.navigateLeft" "Focus left")
    (action "<C-j>" "workbench.action.navigateDown" "Focus below")
    (action "<C-k>" "workbench.action.navigateUp" "Focus above")
    (action "<C-l>" "workbench.action.navigateRight" "Focus right")
    (action "<C-w>v" "workbench.action.splitEditorRight" "Split right")
    (action "<C-w>s" "workbench.action.splitEditorDown" "Split below")
    (action "<C-Up>" "workbench.action.increaseViewHeight" "Increase view height")
    (action "<C-Down>" "workbench.action.decreaseViewHeight" "Decrease view height")
    (action "<C-Left>" "workbench.action.decreaseViewWidth" "Decrease view width")
    (action "<C-Right>" "workbench.action.increaseViewWidth" "Increase view width")
    (action "<C-o>" "workbench.action.navigateBack" "Jump back")
    (action "<C-i>" "workbench.action.navigateForward" "Jump forward")
    (action "<M-m>" "workbench.action.terminal.toggleTerminal" "Toggle terminal")

    (action "gd" "editor.action.revealDefinition" "Definition")
    (action "gD" "editor.action.revealDeclaration" "Declaration")
    (action "gr" "editor.action.goToReferences" "References")
    (action "gi" "editor.action.goToImplementation" "Implementation")
    (action "gh" "editor.showTypeHierarchy" "Type hierarchy")
    (action "K" "editor.action.showHover" "Hover")
    (action "<leader>lr" "editor.action.rename" "Rename")
    (action "<leader>la" "editor.action.quickFix" "Code action")
    (action "<leader>lf" "editor.action.formatDocument" "Format document")
    (action "<leader>ld" "editor.action.showHover" "Hover diagnostic")
    {
      mode = "n";
      key = "<leader>lH";
      action = lib.nixvim.mkRaw ''
        function()
          local code = require("vscode")
          local enabled = code.get_config("editor.inlayHints.enabled")
          code.update_config("editor.inlayHints.enabled", enabled == "off" and "on" or "off", "global")
        end
      '';
      options.desc = "Toggle inlay hints";
    }
    ((action "<leader>/" "editor.action.commentLine" "Toggle comment") // {mode = ["n" "x"];})

    (action "[c" "workbench.action.editor.previousChange" "Previous Git change")
    (action "]c" "workbench.action.editor.nextChange" "Next Git change")
    ((action "<leader>hs" "git.stageSelectedRanges" "Stage selected changes") // {mode = ["n" "x"];})
    ((action "<leader>hr" "git.revertSelectedRanges" "Revert selected changes") // {mode = ["n" "x"];})
    (action "<leader>hS" "git.stage" "Stage file")
    (action "<leader>hu" "git.unstage" "Unstage file")
    (action "<leader>hd" "git.openChange" "Open diff")
  ];

  extraConfigLua = ''
    if vim.g.vscode then
      vim.g.clipboard = vim.g.vscode_clipboard
    end
    -- Avoid waiting for the built-in grn/gra/... prefixes after our gr mapping.
    for _, key in ipairs({ "grn", "gra", "grr", "gri", "grt" }) do
      pcall(vim.keymap.del, "n", key)
    end
  '';
}
