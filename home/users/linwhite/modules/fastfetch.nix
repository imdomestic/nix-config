{...}: {
  programs.fastfetch = {
    enable = true;
    settings = {
      display = {
        separator = " ";
        key = {
          type = "both";
          width = 11;
        };
        color.keys = "blue";
        percent = {
          type = ["bar" "bar-monochrome" "num" "num-color"];
          ndigits = 0;
        };
        bar = {
          width = 16;
          char = {
            elapsed = "━";
            total = "━";
          };
          border = null;
          color = {
            elapsed = "auto";
            total = "90";
          };
        };
      };
      modules = [
        "break"
        "break"
        "break"
        "break"
        "title"
        {
          type = "os";
          key = "OS";
        }
        {
          type = "uptime";
          key = "Uptime";
        }
        {
          type = "memory";
          key = "Memory";
        }
        {
          type = "swap";
          key = "Swap";
        }
        {
          type = "disk";
          key = "Disk";
          folders = "/";
        }
        {
          type = "localip";
          key = "IP";
        }
        {
          type = "battery";
          key = "Battery";
        }
        {
          type = "poweradapter";
          key = "Power";
        }
      ];
    };
  };
}
