{
  config,
  lib,
  pkgs,
  ...
}: let
  ghostty = config.programs.ghostty;
  last = value: lib.last (lib.toList value);
  fonts = lib.toList ghostty.settings.font-family;
  zenId = "custom-F26A132B-4D31-47EB-87D9-24AED11165C4";
  pearlId = "custom-26E5B310-00BF-40B2-98BC-0268B1FCC6EF";
  rexCliDir = "${config.home.homeDirectory}/Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS";
  # tmux-style copy mode: the pane's scrollback in a read-only nvim.
  copyMode = pkgs.writeShellScript "rex-copy-mode" ''
    set -eu
    rex="''${REX_BIN_DIR:-${rexCliDir}}/rex"
    target=$1
    file=$(mktemp -t rex-copy-mode)
    # The app does not follow the focus the server restores when a layer closes.
    trap 'rm -f "$file"; "$rex" focus "$target" >/dev/null 2>&1 || true' EXIT
    "$rex" capture -b "$target" --unwrap --trim >"$file"
    # y leaves after yanking, like tmux's copy-selection-and-cancel; "+ is OSC 52.
    ${lib.getExe' config.programs.nixvim.build.package "nvim"} -R -n \
      -c 'setlocal buftype=nofile nonumber norelativenumber signcolumn=no' \
      -c 'normal! Gzb' \
      -c 'nnoremap <buffer> <nowait> q <Cmd>qa!<CR>' \
      -c 'xnoremap <buffer> y "+y<Cmd>qa!<CR>' \
      -- "$file"
  '';
  themeSource = pkgs.writeText "rex-themes.json" (builtins.toJSON [
    {
      id = zenId;
      name = "Kanso Zen";
      appearance = "dark";
      colors = ghostty.themes.${last ghostty.settings.theme};
    }
    {
      id = pearlId;
      name = "Kanso Pearl";
      appearance = "light";
      # https://github.com/webhooked/kanso.nvim/blob/main/extras/ghostty/kanso-pearl
      colors = {
        background = "#f2f1ef";
        foreground = "#22262D";
        cursor-color = "#22262D";
        selection-background = "#e2e1df";
        selection-foreground = "#22262D";
        palette = [
          "0=#22262D"
          "1=#c84053"
          "2=#6f894e"
          "3=#77713f"
          "4=#4d699b"
          "5=#b35b79"
          "6=#597b75"
          "7=#9F9F99"
          "8=#5C6066"
          "9=#d7474b"
          "10=#6e915f"
          "11=#836f4a"
          "12=#6693bf"
          "13=#624c83"
          "14=#5e857a"
          "15=#f2f1ef"
        ];
      };
    }
  ]);
in {
  imports = [./module.nix];

  home.file.".local/bin/rex".source = config.lib.file.mkOutOfStoreSymlink "${rexCliDir}/rex";

  programs.zsh.initContent = lib.mkMerge [
    # Restore the running server's CLI after Nix/Homebrew reorder PATH.
    (lib.mkOrder 2000 ''
      if [[ -n "''${REX_BIN_DIR:-}" ]]; then
        path=("$REX_BIN_DIR" $path)
      fi
    '')
    # Rex reads OSC 7 (cwd) and OSC 133 (prompt marks) but ships no shell
    # integration; Ghostty's own only loads inside Ghostty.
    (lib.mkOrder 2000 ''
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
        # First in line, so $? is still the command's status.
        precmd_functions=(__rex_precmd $precmd_functions)
        preexec_functions+=(__rex_preexec)
      fi
    '')
  ];

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
        "ctrl+b>${key}" = {
          action = "pane.focus";
          args = {
            inherit direction;
            wrap = true;
          };
        };
        "ctrl+b>shift+${key}" = {
          action = "tmux_swap";
          args = {inherit direction;};
        };
        "ctrl+b>${direction}" = {
          action = "pane.resize";
          args = {
            inherit direction;
            amount = 5;
          };
        };
      })
      directions
      // builtins.listToAttrs (map (index: {
        name = "ctrl+b>${toString index}";
        value = {
          action = "client.tab.goto";
          args = {inherit index;};
        };
      }) (lib.range 1 9))
      // {
        "ctrl+b>c" = bind "client.tab.new";
        "ctrl+b>n" = bind "client.tab.next";
        "ctrl+b>p" = bind "client.tab.previous";
        "ctrl+b>," = bind "client.tab.rename";
        "ctrl+b>shift+," = bind "client.tab.move.backward";
        "ctrl+b>shift+." = bind "client.tab.move.forward";
        "ctrl+b>shift+5" = {
          action = "pane.split";
          args.direction = "right";
        };
        "ctrl+b>shift+'" = {
          action = "pane.split";
          args.direction = "down";
        };
        "ctrl+b>[" = bind "copy_mode";
        "ctrl+b>z" = bind "pane.zoom";
        "ctrl+b>o" = bind "pane.focus_next";
        "ctrl+b>x" = bind "pane.close";
        "ctrl+b>shift+1" = bind "pane.move_to_new_tab";
        "ctrl+b>s" = bind "session.switch";
        "ctrl+b>shift+4" = bind "session.rename";
        "ctrl+b>shift+;" = bind "client.palette.toggle";
        "ctrl+b>d" = bind "client.window.close";
        "ctrl+b>r" = bind "client.config.reload";
        "ctrl+b>ctrl+b" = {
          action = "pane.send_key";
          args.key = "ctrl+b";
        };
      };
    # Rex's pane.move restructures splits; tmux swaps their contents instead.
    # copy_mode floats over the window instead of splitting the pane, so the
    # pane is not resized and its program does not redraw.
    extraConfig = ''
      rex.action{
        name = "tmux_swap",
        title = "Swap with Adjacent Pane",
        category = "Pane",
        args = { direction = "string" },
        repeats = true,
        run = function(ctx, args)
          local function focused()
            local view = assert(rex.session.view{})
            for _, window in ipairs(view.windows or {}) do
              if window.window_id == view.active_window_id then
                return window.focused_block_id
              end
            end
          end
          local original = focused()
          if not original then return end
          assert(rex.session.focus_direction{ direction = args.direction, wrap = true })
          local neighbor = focused()
          if neighbor and neighbor ~= original then
            assert(rex.session.swap_blocks{
              block_id = original, other_block_id = neighbor,
            })
            assert(rex.session.focus_block{ block_id = original })
          end
        end,
      }

      rex.action{
        name = "copy_mode",
        title = "Copy Mode",
        category = "Pane",
        run = function(ctx)
          local target = assert(ctx.block_id, "no focused pane")
          local view = assert(rex.session.view{})
          for _, window in ipairs(view.windows or {}) do
            for _, layer in ipairs(window.layers or {}) do
              for _, block in ipairs(layer.blocks or {}) do
                if block.block_id == target then
                  -- Not the pane's rect: Rex 1443 draws no floating layer that
                  -- starts right of the window's left edge (docs/rex.md#copy-mode).
                  assert(rex.session.new_layer{
                    window_id = window.window_id,
                    bounds = { 0, 0, 1, 1 },
                    focus = true,
                    layout = rex.layout.block{
                      flavor = "com.superlogical.terminal.shell",
                      options = { command = { "${copyMode}", target }, shell = "none" },
                    },
                  })
                  return
                end
              end
            end
          end
          error("focused pane is not in this session's layout", 0)
        end,
      }
    '';
  };

  home.activation.reloadRexConfig = lib.hm.dag.entryAfter ["linkGeneration"] ''
    rexBin="$HOME/Library/Application Support/com.superlogical.rex/RexServer/Versions/Current/Rex Server.app/Contents/MacOS/rex"
    if [[ -x "$rexBin" ]]; then
      run "$rexBin" config check
      if "$rexBin" --autostart=false server status >/dev/null 2>&1; then
        run "$rexBin" --autostart=false config reload
      fi
    fi
  '';

  # Rex 1408 stores appearance in user defaults, separately from init.lua.
  # Migration coverage and remaining differences: docs/rex.md.
  targets.darwin.defaults."com.superlogical.rex" = {
    "Workspace.darkThemeID" = zenId;
    "Workspace.lightThemeID" = pearlId;
    "Workspace.terminalFontName" = lib.head fonts;
    "Workspace.terminalFontPointSize" = last ghostty.settings.font-size;
    "Workspace.terminalFallbackFontNames" = lib.tail fonts;
    "Workspace.terminalCursorStyle" = last ghostty.settings.cursor-style;
    "Workspace.terminalCursorStyleForced" = false;
    "Workspace.terminalCursorBlinkIntervalMilliseconds" = 0;
    "Workspace.terminalCursorBlinkUsesCustomInterval" = false;
    "Workspace.terminalOptionKeyBehavior" = "actsAsAlt";
    "Workspace.terminalUsesDisplayP3" = false;
  };

  # defaults' native module cannot encode NSData; merge only this JSON-data key.
  home.activation.rexTheme = lib.hm.dag.entryAfter ["setDarwinDefaults"] ''
    run ${lib.getExe pkgs.python3} - ${themeSource} <<'PY'
    import json
    import plistlib
    import subprocess
    import sys
    import tempfile
    import time

    domain = "com.superlogical.rex"
    with open(sys.argv[1]) as source:
        theme_specs = json.load(source)

    def color(hex_value):
        rgb = bytes.fromhex(hex_value.lstrip("#"))
        return dict(zip(("red", "green", "blue"), (v / 255 for v in rgb)),
                    alpha=1, colorSpace="srgb")

    # Match Ghostty's standard xterm colors outside the sixteen theme colors.
    levels = (0, 95, 135, 175, 215, 255)
    extended = {}
    for index in range(16, 256):
        if index < 232:
            n = index - 16
            rgb = (levels[n // 36], levels[n // 6 % 6], levels[n % 6])
        else:
            rgb = (8 + 10 * (index - 232),) * 3
        extended[str(index)] = color(bytes(rgb).hex())

    def palette_for(colors):
        def last(key):
            value = colors[key]
            return value[-1] if isinstance(value, list) else value

        palette = {
            "background": color(last("background")),
            "foreground": color(last("foreground")),
            "cursor": color(last("cursor-color")),
            "cursorText": color(last("background")),
            "selectionBackground": color(last("selection-background")),
            "selectionForeground": color(last("selection-foreground")),
            "ansi": [None] * 16,
            "paletteGenerate": False,
            "paletteHarmonious": False,
            "paletteBase": extended,
            "paletteOverrides": {},
        }
        for entry in colors["palette"]:
            index, hex_value = entry.split("=", 1)
            palette["ansi"][int(index)] = color(hex_value)
        return palette

    result = subprocess.run(["/usr/bin/defaults", "export", domain, "-"],
                            capture_output=True, check=True)
    current = plistlib.loads(result.stdout)
    themes = json.loads(current.get("Workspace.customThemes", b"[]"))
    for spec in theme_specs:
        previous = next((t for t in themes if t["id"] == spec["id"]), {})
        theme = {
            "id": spec["id"],
            "name": spec["name"],
            "appearance": spec["appearance"],
            "source": {"manual": {}},
            "createdAt": previous.get("createdAt", time.time() - 978307200),
            "palette": palette_for(spec["colors"]),
        }
        themes = [t for t in themes if t["id"] != spec["id"]] + [theme]
    data = json.dumps(themes, separators=(",", ":")).encode()
    with tempfile.NamedTemporaryFile(suffix=".plist") as output:
        plistlib.dump({"Workspace.customThemes": data}, output)
        output.flush()
        subprocess.run(["/usr/bin/defaults", "import", domain, output.name],
                       check=True)
    PY
  '';
}
