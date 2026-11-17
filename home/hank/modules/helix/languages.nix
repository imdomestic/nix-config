# 从 ../nixvim 的 LSP 设置和 conform 的 formatters_by_ft 搬过来;只写和 helix
# 自带 languages.toml 不一样的部分,其余(clangd、taplo、tinymist、HLS……)用默认。
# 格式化程序不在 PATH 上时 :format 会退回 LSP 格式化。
{
  config,
  lib,
  ...
}: let
  # helix 不展开格式化参数里的文件名,只给扩展名让 biome 认语言;cwd 是文件
  # 所在目录,biome.json 照样找得到。html / markdown 不交给 biome:2.4 默认
  # 不格式化这两种,会直接报错。
  biome = ext: {
    command = "biome";
    args = ["format" "--stdin-file-path=stdin.${ext}"];
  };
  # 同 conform 的 biome-check:格式化 + 整理 import + safe fix。
  biomeCheck = ext: {
    command = "biome";
    args = ["check" "--write" "--stdin-file-path=stdin.${ext}"];
  };
  web = name: ext: {
    inherit name;
    language-servers = ["vtsls" "tailwindcss-ls"];
    formatter = biomeCheck ext;
  };
  spaces = n: {
    tab-width = n;
    unit = lib.strings.replicate n " ";
  };
  pgUser = config.home.username;
in {
  programs.helix.languages = {
    language-server = {
      # 打开 flake.nix 时直接 `nix flake archive`,不再弹窗问。
      nil.config.nil.nix.flake.autoArchive = true;

      vtsls = {
        command = "vtsls";
        args = ["--stdio"];
        config = {
          vtsls.experimental.completion.enableServerSideFuzzyMatch = true;
          typescript = {
            updateImportsOnFileMove.enabled = "always";
            suggest.completeFunctionCalls = true;
            inlayHints = {
              parameterNames.enabled = "literals";
              parameterTypes.enabled = true;
              propertyDeclarationTypes.enabled = true;
              functionLikeReturnTypes.enabled = true;
              variableTypes.enabled = false;
            };
          };
        };
      };

      tailwindcss-ls.config.tailwindCSS.classFunctions = ["cn" "clsx" "cva" "tw" "twMerge"];

      yaml-language-server.config.redhat.telemetry.enabled = false;

      # 连 ../postgresql 的练习库,和 nvim 的 postgres_lsp 同一个。不给 host
      # 它根本不连库。
      postgres-language-server = {
        command = "postgres-language-server";
        args = ["lsp-proxy"];
        config.db = {
          host = "127.0.0.1";
          database = pgUser;
          username = pgUser;
        };
      };

      # 同 rustaceanvim 那份,除了 files.watcher:helix 没有完整的文件监视,
      # 它自带的默认 "server" 要留着。
      rust-analyzer.config = {
        files.exclude = [".git" "target" "node_modules" ".direnv" ".venv" "venv" "dist" "build" ".flatpak-builder"];
        cargo = {
          extraEnv.CARGO_PROFILE_RUST_ANALYZER_INHERITS = "dev";
          extraArgs = ["--profile" "rust-analyzer"];
        };
        checkOnSave = true;
        check = {
          command = "clippy";
          allTargets = false;
          extraArgs = ["--no-deps"];
          allFeatures = true;
        };
        inlayHints = {
          expressionAdjustmentHints.enable = "always";
          implicitDrops.enable = "always";
          implicitSizedBoundHints.enable = true;
        };
      };
    };

    language = [
      {
        name = "nix";
        formatter = {
          command = "alejandra";
          args = ["--quiet"];
        };
      }
      {
        name = "python";
        formatter = {
          command = "ruff";
          args = ["format" "-"];
        };
      }
      {
        name = "typst";
        formatter.command = "typstyle";
      }
      {
        name = "json";
        formatter = biome "json";
      }
      {
        name = "jsonc";
        formatter = biome "jsonc";
      }
      {
        name = "css";
        language-servers = ["vscode-css-language-server" "tailwindcss-ls"];
        formatter = biome "css";
      }
      {
        name = "html";
        language-servers = ["vscode-html-language-server" "tailwindcss-ls"];
      }
      (web "javascript" "js")
      (web "jsx" "jsx")
      (web "typescript" "ts")
      (web "tsx" "tsx")
      {
        name = "haskell";
        formatter = {
          command = "ormolu";
          args = ["--stdin-input-file" "stdin.hs"];
        };
      }
      {
        name = "ocaml";
        formatter = {
          command = "ocamlformat";
          args = ["--enable-outside-detected-project" "--name" "stdin.ml" "-"];
        };
      }
      {
        name = "elm";
        formatter = {
          command = "elm-format";
          args = ["--stdin"];
        };
      }
      {
        name = "swift";
        formatter = {
          command = "swiftformat";
          args = ["--stdinpath" "stdin.swift"];
        };
      }
      {
        name = "sql";
        language-servers = ["postgres-language-server"];
      }
      # 同 nvim 的 after/ftplugin;只列 helix 默认不一样的。文件里已有缩进时
      # helix 自己会探测(像 sleuth),.editorconfig 也认。
      {
        name = "c";
        indent = spaces 4;
      }
      {
        name = "java";
        indent = spaces 4;
      }
      {
        name = "c-sharp";
        indent = spaces 4;
      }
    ];
  };
}
