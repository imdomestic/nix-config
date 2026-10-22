{...}: {
  # 保留 linwhite 原 prompt 的布局、符号和时间设置，颜色由 flat-white 提供。
  programs.starship.settings = {
    right_format = "$time$battery";
    command_timeout = 10000;
    add_newline = true;
    container = {
      format = ''[$symbol \[$name\]]($style) '';
      symbol = "⬢";
    };
    terraform.format = "[🏎💨 $version$workspace]($style) ";
    battery = {
      full_symbol = "🔋 ";
      charging_symbol = "⚡️ ";
      discharging_symbol = "💀 ";
      display = [
        {
          threshold = 100;
          style = "bold red";
        }
      ];
    };
    username = {
      show_always = true;
      style_user = "bright-blue";
      format = "[$user]($style) ";
    };
    sudo = {
      style = "bold green";
      symbol = "👩‍💻 ";
      disabled = false;
    };
    time = {
      disabled = false;
      format = ''🕙[\[ $time \]]($style) '';
      time_format = "%T";
      utc_time_offset = "+8";
      time_range = "00:00:00-24:00:00";
    };
    os = {
      format = "[$symbol]($style) ";
      style = "bold blue";
      disabled = false;
      symbols = {
        Alpaquita = " ";
        Alpine = " ";
        Amazon = " ";
        Android = " ";
        Arch = " ";
        Artix = " ";
        CentOS = " ";
        Debian = " ";
        DragonFly = " ";
        Emscripten = " ";
        EndeavourOS = " ";
        Fedora = " ";
        FreeBSD = " ";
        Garuda = "󰛓 ";
        Gentoo = " ";
        HardenedBSD = "󰞌 ";
        Illumos = "󰈸 ";
        Linux = " ";
        Mabox = " ";
        Macos = " ";
        Manjaro = " ";
        Mariner = " ";
        MidnightBSD = " ";
        Mint = " ";
        NetBSD = " ";
        NixOS = " ";
        OpenBSD = "󰈺 ";
        openSUSE = " ";
        OracleLinux = "󰌷 ";
        Pop = " ";
        Raspbian = " ";
        Redhat = " ";
        RedHatEnterprise = " ";
        Redox = "󰀘 ";
        Solus = "󰠳 ";
        SUSE = " ";
        Ubuntu = " ";
        Unknown = " ";
        Windows = "󰍲 ";
      };
    };
    c = {
      format = "via [$symbol $version]($style)";
      detect_extensions = ["c" "h" "cc" "cpp" "hh" "hpp"];
      symbol = " ";
    };
    cmake = {
      format = "via [$symbol($version )]($style)";
      symbol = " ";
    };
    directory.read_only = " 󰌾";
    docker_context.symbol = " ";
    fossil_branch.symbol = " ";
    git_branch.symbol = " ";
    lua = {
      format = "via [$symbol($version )]($style)";
      symbol = "🌙 ";
    };
    memory_usage.symbol = "󰍛 ";
    nodejs.symbol = " ";
    package.symbol = "󰏗 ";
    python = {
      format = ''via [''${symbol}''${pyenv_prefix}(''${version} )(\($virtualenv\) )]($style)'';
      symbol = "🐍 ";
    };
    rust = {
      format = "via [$symbol $version](red bold)";
      symbol = "🦀";
    };
  };
}
