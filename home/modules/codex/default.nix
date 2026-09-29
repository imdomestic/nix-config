{pkgs, ...}: {
  # tmTheme 是语法高亮资源;当前 HM 的 Codex 模块没有 themes 选项。
  home.file.".codex/themes/evergarden-winter.tmTheme".source = pkgs.fetchurl {
    url = "https://raw.githubusercontent.com/evergardentheme/bat/aa5b92e927d1169673050f4f444496590e053487/themes/evergarden-winter.tmTheme";
    hash = "sha256-jZ6Rc6ScIffy73FQJn8FYqJG5pS/6plk4oqJModbxKw=";
  };
  home.file.".codex/themes/kanso-zen.tmTheme".source = import ./kanso-zen.nix {inherit pkgs;};
}
