{
  config,
  lib,
  pkgs,
  ...
}: let
  ghostty = config.programs.ghostty.settings;
  fonts = lib.toList ghostty.font-family;
  last = value: lib.last (lib.toList value);
  palette = import ../flat-white/palette.nix;
  themeId = "custom-04322156-B3B4-4897-9DEA-BA85CABECDB1";
  rexCliDir = "${config.home.homeDirectory}/Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS";
  themeSource = pkgs.writeText "rex-flat-white.json" (builtins.toJSON {
    id = themeId;
    inherit (palette) name colors ansi;
  });
  copyMode = pkgs.writeShellScript "rex-copy-mode" ''
    set -eu
    mkdir -p ${lib.escapeShellArg "${config.xdg.cacheHome}/rex"}
    file=$(mktemp ${lib.escapeShellArg "${config.xdg.cacheHome}/rex/scrollback.XXXXXXXX"})
    trap 'rm -f "$file"' EXIT
    "''${REX_BIN_DIR:-${rexCliDir}}/rex" capture -b "$1" --unwrap --trim >"$file"
    ${lib.getExe' config.programs.nixvim.build.package "nvim"} -u NONE -i NONE -R -n \
      --cmd "let g:clipboard = 'osc52'" \
      -c 'setlocal buftype=nofile nonumber norelativenumber signcolumn=no' \
      -c 'normal! Gzb' \
      -c 'nnoremap <buffer> <nowait> q <Cmd>qa!<CR>' \
      -c 'xnoremap <buffer> y "+y<Cmd>qa!<CR>' \
      -- "$file"
  '';
in {
  imports = [./module.nix];

  home.file.".local/bin/rex".source = config.lib.file.mkOutOfStoreSymlink "${rexCliDir}/rex";

  programs.wezterm.enableZshIntegration = false;

  programs.rex = {
    enable = true;
    bindings = let
      bind = action: {inherit action;};
      directions = {
        h = "left";
        j = "down";
        k = "up";
        l = "right";
      };
    in
      lib.concatMapAttrs (key: direction: {
        "ctrl+a>${key}" = {
          action = "pane.focus";
          args = {inherit direction;};
        };
        "ctrl+a>${direction}" = {
          action = "pane.focus";
          args = {inherit direction;};
        };
        "ctrl+a>ctrl+${direction}" = {
          action = "pane.resize";
          args = {inherit direction; amount = 5;};
        };
        "ctrl+shift+${key}" = {
          action = "pane.focus";
          args = {inherit direction;};
        };
      }) directions
      // builtins.listToAttrs (map (index: {
        name = "ctrl+a>${toString index}";
        value = {
          action = "client.tab.goto";
          args = {inherit index;};
        };
      }) (lib.range 1 9))
      // {
        "ctrl+a>c" = bind "client.tab.new";
        "ctrl+a>n" = bind "client.tab.next";
        "ctrl+a>p" = bind "client.tab.previous";
        "ctrl+a>," = bind "client.tab.rename";
        "ctrl+a>[Comma]" = bind "client.tab.rename";
        "ctrl+a>shift+\\" = {action = "pane.split"; args.direction = "right";};
        "ctrl+a>shift+[Backslash]" = {action = "pane.split"; args.direction = "right";};
        "ctrl+a>shift+5" = {action = "pane.split"; args.direction = "right";};
        "ctrl+a>-" = {action = "pane.split"; args.direction = "down";};
        "ctrl+a>shift+'" = {action = "pane.split"; args.direction = "down";};
        "ctrl+a>shift+[Quote]" = {action = "pane.split"; args.direction = "down";};
        "ctrl+a>[" = bind "copy_mode";
        "ctrl+a>[BracketLeft]" = bind "copy_mode";
        "ctrl+a>z" = bind "pane.zoom";
        "ctrl+a>o" = bind "pane.focus_next";
        "ctrl+a>x" = bind "pane.close";
        "ctrl+a>s" = bind "session.switch";
        "ctrl+a>shift+4" = bind "session.rename";
        "ctrl+a>shift+;" = bind "client.palette.toggle";
        "ctrl+a>shift+[Semicolon]" = bind "client.palette.toggle";
        "ctrl+a>d" = bind "client.window.close";
        "ctrl+a>r" = bind "client.config.reload";
        "ctrl+a>ctrl+a" = {action = "pane.send_key"; args.key = "ctrl+a";};
        "ctrl+a>a" = {action = "pane.send_key"; args.key = "ctrl+a";};
      };
    extraConfig = ''
      local function rect_of(node, block_id)
        if node == nil then return nil end
        if node.block_id == block_id then return node.rect end
        if node.split then
          return rect_of(node.split.before, block_id)
            or rect_of(node.split.after, block_id)
        end
      end

      rex.action{
        name = "copy_mode",
        title = "Copy Mode",
        category = "Pane",
        run = function()
          local view = assert(rex.session.view{})
          local current
          for _, window in ipairs(view.windows) do
            if window.window_id == view.active_window_id then
              current = window
              break
            end
          end
          assert(current, "no active window")
          local target = assert(current.focused_block_id, "no focused pane")
          for _, layer in ipairs(current.layers) do
            local rect = rect_of(layer.layout, target)
            if rect then
              if current.zoomed_block_id == target then rect = { 0, 0, 1, 1 } end
              assert(rex.session.new_layer{
                window_id = current.window_id,
                bounds = rect,
                focus = true,
                layout = rex.layout.block{
                  flavor = "com.superlogical.terminal.shell",
                  options = { command = { "${copyMode}", target }, shell = "none" },
                },
              })
              return
            end
          end
          error("focused pane is not in this session's layout", 0)
        end,
      }
    '';
  };

  targets.darwin.defaults."com.superlogical.rex" = {
    "Workspace.darkThemeID" = themeId;
    "Workspace.terminalFontName" = lib.head fonts;
    "Workspace.terminalFallbackFontNames" = lib.tail fonts;
    "Workspace.terminalFontPointSize" = last ghostty.font-size;
    "Workspace.terminalCursorStyle" = last ghostty.cursor-style;
    "Workspace.terminalCursorStyleForced" = false;
    "Workspace.terminalCursorBlinkIntervalMilliseconds" = 0;
    "Workspace.terminalCursorBlinkUsesCustomInterval" = false;
    "Workspace.terminalOptionKeyBehavior" = "actsAsAlt";
    "Workspace.terminalUsesDisplayP3" = false;
  };

  # 自定义主题以 NSData 保存，原生 defaults 模块负责其余偏好设置。
  home.activation.rexFlatWhite = lib.hm.dag.entryAfter ["setDarwinDefaults"] ''
    run ${lib.getExe pkgs.python3} ${./rex-theme.py} ${themeSource}
  '';

  home.activation.reloadRexConfig = lib.hm.dag.entryAfter ["linkGeneration"] ''
    rexBin=${lib.escapeShellArg "${rexCliDir}/rex"}
    if [[ -x "$rexBin" ]]; then
      run "$rexBin" config check
      if "$rexBin" --autostart=false server status >/dev/null 2>&1; then
        run "$rexBin" --autostart=false config reload
      fi
    fi
  '';

  programs.zsh.initContent = lib.mkOrder 2000 ''
    ${lib.optionalString config.programs.wezterm.enable ''
      if [[ $TERM_PROGRAM == WezTerm ]]; then
        source "${config.programs.wezterm.package}/etc/profile.d/wezterm.sh"
      fi
    ''}
    if [[ -n "''${REX_BIN_DIR:-}" ]]; then
      path=("$REX_BIN_DIR" $path)
    fi
    if [[ $TERM_PROGRAM == rex ]]; then
      typeset -gi __rex_cmd_ran=0
      __rex_osc7() {
        emulate -L zsh
        setopt extendedglob
        local LC_ALL=C
        builtin printf '\e]7;file://%s%s\e\\' "$HOST" \
          "''${PWD//(#m)([^@-Za-z&-;_~])/%''${(l:2::0:)$(([##16]#MATCH))}}"
      }
      __rex_precmd() {
        local ret=$?
        if (( __rex_cmd_ran )); then
          builtin printf '\e]133;D;%d\a' $ret
          __rex_cmd_ran=0
        fi
        __rex_osc7
        builtin printf '\e]133;A\a'
        [[ $PS1 == *$'\e]133;B\a'* ]] || PS1+=$'%{\e]133;B\a%}'
        return $ret
      }
      __rex_preexec() {
        __rex_cmd_ran=1
        builtin printf '\e]133;C\a'
      }
      precmd_functions=(__rex_precmd $precmd_functions)
      preexec_functions+=(__rex_preexec)
    fi
  '';
}
