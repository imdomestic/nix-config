{
  pkgs,
  lib,
  ...
}: {
  home.packages = [pkgs.zsh-completions];

  programs.zsh = {
    enableCompletion = true;
    autocd = true;
    defaultKeymap = "viins";

    autosuggestion = {
      enable = true;
      highlight = "fg=#585B70,bold";
    };

    historySubstringSearch.enable = true;

    syntaxHighlighting = {
      enable = true;
      highlighters = ["main" "brackets" "pattern" "cursor" "regexp" "root" "line"];
    };

    history = {
      size = 10000;
      save = 10000;
      path = "$HOME/.cache/zsh/.zhistory";
      share = true;
      extended = true;
      ignoreSpace = true;
      ignoreAllDups = true;
      saveNoDups = true;
      expireDuplicatesFirst = true;
    };

    setOptions = [
      "AUTO_MENU"
      "AUTO_PARAM_SLASH"
      "COMPLETE_IN_WORD"
      "NO_MENU_COMPLETE"
      "HASH_LIST_ALL"
      "ALWAYS_TO_END"
      "NOTIFY"
      "NOHUP"
      "MAILWARN"
      "INTERACTIVE_COMMENTS"
      "NOBEEP"
      "HIST_NO_FUNCTIONS"
      "HIST_REDUCE_BLANKS"
      "NO_FLOW_CONTROL"
      "NO_NOMATCH"
      "NO_CORRECT"
      "NO_EQUALS"
    ];

    plugins = [
      {
        name = "zsh-autopair";
        src = pkgs.zsh-autopair;
        file = "share/zsh/zsh-autopair/autopair.zsh";
      }
      {
        name = "zsh-you-should-use";
        src = pkgs.zsh-you-should-use;
        file = "share/zsh/plugins/you-should-use/you-should-use.plugin.zsh";
      }
      {
        name = "fzf-tab";
        src = pkgs.zsh-fzf-tab;
        file = "share/fzf-tab/fzf-tab.plugin.zsh";
      }
      {
        name = "zsh-history-search-multi-word";
        src = pkgs.zsh-history-search-multi-word;
        file = "share/zsh/zsh-history-search-multi-word/history-search-multi-word.plugin.zsh";
      }
    ];

    shellAliases = {
      # jj (jujutsu)
      jdesc = "jj desc";
      jn = "jj new";
      jst = "jj st";
      jl = "jj log";
      jc = "jj commit";
      ja = "jj abandon";
      jsq = "jj squash";
      jd = "jj diff";
      je = "jj edit";
      jne = "jj next";
      jgi = "jj git init";
      jgp = "jj git push";
      jgf = "jj git fetch";
      jgcl = "jj git clone --colocate";

      # editors
      nvimdiff = "nvim -d";
      p = "git add . && git commit -am 'update' && git push -u origin main";
      getidf = "source ~/esp/esp-idf/export.sh";
      brew86 = "arch -x86_64 /usr/local/homebrew/bin/brew";
      lg = "lazygit";
      kvim = "NVIM_APPNAME=kvim nvim";
      hvim = "NVIM_APPNAME=hvim nvim";
      lvim = "NVIM_APPNAME=lazyvim nvim";
      dvim = "NVIM_APPNAME=dvim nvim";
      ra = "joshuto";
      nvid = "neovide --frame buttonless --title-hidden";

      # general
      settings = "gnome-control-center";
      run = "pnpm run";
      c = "clear";
      q = "exit";
      cleanram = "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'";
      trim_all = "sudo fstrim -va";
      mkgrub = "sudo grub-mkconfig -o /boot/grub/grub.cfg";
      mtar = "tar -zcvf";
      utar = "tar -zxvf";
      uz = "unzip";
      ".." = "cd ..";
      psg = "ps aux | grep -v grep | grep -i -e VSZ -e";
      mkdir = "mkdir -p";
      fm = "ranger";

      # pacman / paru
      pacin = ''pacman -Slq | fzf -m --preview 'cat <(pacman -Si {1}) <(pacman -Fl {1} | awk "{print $2}")' | xargs -ro sudo pacman -S'';
      paruin = ''paru -Slq | fzf -m --preview 'cat <(paru -Si {1}) <(paru -Fl {1} | awk "{print $2}")' | xargs -ro paru -S'';
      pacrem = ''pacman -Qq | fzf --multi --preview 'pacman -Qi {1}' | xargs -ro sudo pacman -Rns'';
      pac = "pacman -Q | fzf";
      parucom = "paru -Gc";
      parupd = "paru -Qua";
      pacupd = "pacman -Qu";
      parucheck = "paru -Gp";
      cleanpac = "sudo pacman -Rns $(pacman -Qtdq); paru -c";
      installed = "grep -i installed /var/log/pacman.log";

      # file operations
      ls = "eza --color=auto --icons";
      l = "ls -l";
      la = "ls -a";
      lla = "ls -la";
      lt = "ls --tree";
      cat = "bat --color always --plain";
      grep = "grep --color=auto --exclude-dir={.bzr,CVS,.git,.hg,.svn,.idea,.tox}";
      mv = "mv -v";
      cp = "cp -vr";
      rm = "rm -vr";

      # git basics
      commit = "git add . && git commit -m";
      push = "git push";
      git-rm = "git ls-files --deleted -z | xargs -0 git rm";
      g = "git";
      ga = "git add";
      gaa = "git add --all";
      gam = "git am";
      gama = "git am --abort";
      gamc = "git am --continue";
      gams = "git am --skip";
      gamscp = "git am --show-current-patch";
      gap = "git apply";
      gapa = "git add --patch";
      gapt = "git apply --3way";
      gau = "git add --update";
      gav = "git add --verbose";

      # git branch
      gb = "git branch";
      gbD = "git branch -D";
      gba = "git branch -a";
      gbd = "git branch -d";
      gbda = ''git branch --no-color --merged | command grep -vE "^([+*]|\s*($(git_main_branch)|$(git_develop_branch))\s*$)" | command xargs git branch -d 2>/dev/null'';
      gbl = "git blame -b -w";
      gbnm = "git branch --no-merged";
      gbr = "git branch --remote";

      # git bisect
      gbs = "git bisect";
      gbsb = "git bisect bad";
      gbsg = "git bisect good";
      gbsr = "git bisect reset";
      gbss = "git bisect start";

      # git commit
      gc = "git commit -v";
      "gc!" = "git commit -v --amend";
      gca = "git commit -v -a";
      "gca!" = "git commit -v -a --amend";
      gcam = "git commit -a -m";
      "gcan!" = "git commit -v -a --no-edit --amend";
      "gcans!" = "git commit -v -a -s --no-edit --amend";
      gcas = "git commit -a -s";
      gcasm = "git commit -a -s -m";
      gcmsg = "git commit -m";
      "gcn!" = "git commit -v --no-edit --amend";
      gcs = "git commit -S";
      gcsm = "git commit -s -m";
      gcss = "git commit -S -s";
      gcssm = "git commit -S -s -m";

      # git checkout
      gcb = "git checkout -b";
      gcd = "git checkout $(git_develop_branch)";
      gcf = "git config --list";
      gcl = "git clone";
      gcld = "git clone --depth";
      gclr = "git clone --recurse-submodules";
      gclean = "git clean -id";
      gcm = "git checkout $(git_main_branch)";
      gco = "git checkout";
      gcor = "git checkout --recurse-submodules";
      gcount = "git shortlog -sn";

      # git cherry-pick
      gcp = "git cherry-pick";
      gcpa = "git cherry-pick --abort";
      gcpc = "git cherry-pick --continue";

      # git diff
      gd = "git diff";
      gdca = "git diff --cached";
      gdct = "git describe --tags $(git rev-list --tags --max-count=1)";
      gdcw = "git diff --cached --word-diff";
      gds = "git diff --staged";
      gdt = "git diff-tree --no-commit-id --name-only -r";
      gdup = "git diff @{upstream}";
      gdw = "git diff --word-diff";

      # git fetch
      gf = "git fetch";
      gfa = "git fetch --all --prune --jobs=10";
      gfg = "git ls-files | grep";
      gfo = "git fetch origin";

      # git gui
      gg = "git gui citool";
      gga = "git gui citool --amend";

      # git pull/push
      ggpull = ''git pull origin "$(git_current_branch)"'';
      ggpur = "ggu";
      ggpush = ''git push origin "$(git_current_branch)"'';
      ggsup = "git branch --set-upstream-to=origin/$(git_current_branch)";
      ghh = "git help";
      gl = "git pull";
      gp = "git push";
      gpd = "git push --dry-run";
      gpf = "git push --force-with-lease";
      "gpf!" = "git push --force";
      gpoat = "git push origin --all && git push origin --tags";
      gpr = "git pull --rebase";
      gpristine = "git reset --hard && git clean -dffx";
      gpsup = "git push --set-upstream origin $(git_current_branch)";
      gpu = "git push upstream";
      gpv = "git push -v";
      gup = "git pull --rebase";
      gupa = "git pull --rebase --autostash";
      gupav = "git pull --rebase --autostash -v";
      gupv = "git pull --rebase -v";
      glum = "git pull upstream $(git_main_branch)";

      # git ignore
      gignore = "git update-index --assume-unchanged";
      gignored = ''git ls-files -v | grep "^[[:lower:]]"'';
      gunignore = "git update-index --no-assume-unchanged";

      # git log
      glg = "git log --stat";
      glgg = "git log --graph";
      glgga = "git log --graph --decorate --all";
      glgm = "git log --graph --max-count=10";
      glgp = "git log --stat -p";
      glo = "git log --oneline --decorate";
      globurl = "noglob urlglobber ";
      glod = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ad) %C(bold blue)<%an>%Creset'";
      glods = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ad) %C(bold blue)<%an>%Creset' --date=short";
      glog = "git log --oneline --decorate --graph";
      gloga = "git log --oneline --decorate --graph --all";
      glol = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset'";
      glola = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset' --all";
      glols = "git log --graph --pretty='%Cred%h%Creset -%C(auto)%d%Creset %s %Cgreen(%ar) %C(bold blue)<%an>%Creset' --stat";
      glp = "_git_log_prettily";

      # git merge
      gm = "git merge";
      gma = "git merge --abort";
      gmom = "git merge origin/$(git_main_branch)";
      gmtl = "git mergetool --no-prompt";
      gmtlvim = "git mergetool --no-prompt --tool=vimdiff";
      gmum = "git merge upstream/$(git_main_branch)";

      # git rebase
      grb = "git rebase";
      grba = "git rebase --abort";
      grbc = "git rebase --continue";
      grbd = "git rebase $(git_develop_branch)";
      grbi = "git rebase -i";
      grbm = "git rebase $(git_main_branch)";
      grbo = "git rebase --onto";
      grbom = "git rebase origin/$(git_main_branch)";
      grbs = "git rebase --skip";

      # git remote
      gr = "git remote";
      gra = "git remote add";
      grmv = "git remote rename";
      grrm = "git remote remove";
      grset = "git remote set-url";
      grup = "git remote update";
      grv = "git remote -v";

      # git reset/restore
      grh = "git reset";
      grhh = "git reset --hard";
      groh = "git reset origin/$(git_current_branch) --hard";
      grs = "git restore";
      grss = "git restore --source";
      grst = "git restore --staged";
      gru = "git reset --";

      # git rm
      grm = "git rm";
      grmc = "git rm --cached";
      grwh = "git rm --cached $(git ls-files -i -c --exclude-from=.gitignore)";
      grwhx = "git ls-files -i -c --exclude-from=.gitignore | xargs git rm --cached";
      grad = "git rm -r --cached . && git add .";

      # git show/status
      gsh = "git show";
      gsps = "git show --pretty=short --show-signature";
      gsb = "git status -sb";
      gss = "git status -s";
      gst = "git status";

      # git stash
      gsta = "git stash push";
      gstaa = "git stash apply";
      gstall = "git stash --all";
      gstc = "git stash clear";
      gstd = "git stash drop";
      gstl = "git stash list";
      gstp = "git stash pop";
      gsts = "git stash show --text";
      gstu = "gsta --include-untracked";

      # git submodule
      gsi = "git submodule init";
      gsu = "git submodule update";

      # git switch
      gsw = "git switch";
      gswc = "git switch -c";
      gswd = "git switch $(git_develop_branch)";
      gswm = "git switch $(git_main_branch)";

      # git svn
      gsd = "git svn dcommit";
      gsr = "git svn rebase";
      git-svn-dcommit-push = "git svn dcommit && git push github $(git_main_branch):svntrunk";

      # git tag
      gtl = "noglob _gtl";
      gts = "git tag -s";
      gtv = "git tag | sort -V";

      # git misc
      grt = ''cd "$(git rev-parse --show-toplevel || echo .)"'';
      grev = "git revert";
      gk = "\\gitk --all --branches &!";
      gke = "\\gitk --all $(git log -g --pretty=%h) &!";
      gwch = "git whatchanged -p --abbrev-commit --pretty=medium";
      gwip = ''git add -A; git rm $(git ls-files --deleted) 2> /dev/null; git commit --no-verify --no-gpg-sign -m "--wip-- [skip ci]"'';
      gunwip = ''git log -n 1 | grep -q -c "\-\-wip\-\-" && git reset HEAD~1'';
    };

    envExtra = ''
      export PATH="$HOME/.moon/bin:$PATH"
      export PATH="$HOME/.ghcup/bin:$PATH"
      export PATH="$HOME/.local/bin:$PATH"
      export PATH="$HOME/.cargo/bin:$PATH"

      export KUBECONFIG="$HOME/.config/k3s.yaml"
      export TERMINAL="ghostty"

      export XDG_CONFIG_HOME="$HOME/.config"
      export XDG_CACHE_HOME="$HOME/.cache"
      export XDG_DATA_HOME="$HOME/.local/share"
      export XDG_STATE_HOME="$HOME/.local/state"
    '';

    initContent = lib.mkMerge [
      (lib.mkBefore ''
        ZSH_AUTOSUGGEST_USE_ASYNC="true"
      '')
      (lib.mkOrder 550 ''
        zmodload zsh/zle
        zmodload zsh/zpty
        zmodload zsh/complist
      '')
      ''
        ${builtins.readFile ./init-extra.zsh}
      ''
    ];
  };
}
