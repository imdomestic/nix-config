# 管好你自己的 home —— 新手指南

写给 **kenneth** 和 **fendada**。看完这一篇就够用了,不需要先学会 Nix。

---

## 0. 先搞清楚一件事:系统和你,是分开的

这个仓库管两样东西:

| | 是什么 | 谁改 |
| --- | --- | --- |
| **系统配置** | 机器本身:内核、服务、防火墙、创建哪些账号 | hank |
| **home 配置** | 你的账号:装什么命令行工具、shell 长什么样、git 用户名、编辑器 | **你** |

**这两样现在是完全独立的两份东西。** 这意味着:

- 你改自己的配置 **不需要 root**,不用 sudo,不会影响机器上任何别人。
- 你改自己的配置 **不会重启任何服务**,不会把机器搞挂。最坏的情况是你自己的 shell
  变得不好用,再改回来就行。
- 反过来:hank 重装整台机器也**不会**动你的 home。你的东西要生效,始终得你自己跑一次命令。

所以你能造成的最大破坏,就是把你自己的终端弄难看。放心改。

---

## 1. 你在哪些机器上

**kenneth** —— 三台服务器,配置完全一样:

| 机器 | 你的配置名 |
| --- | --- |
| h610 | `kenneth@h610` |
| shanghai | `kenneth@shanghai` |
| tank | `kenneth@tank` |

**fendada** —— 三台服务器 + 你自己的 Mac:

| 机器 | 你的配置名 | 备注 |
| --- | --- | --- |
| h610 | `fendada@h610` | 装了完整的一套工具 |
| shanghai | `fendada@shanghai` | 精简版,**没有 `just` 命令** |
| tank | `fendada@tank` | 精简版,**没有 `just` 命令** |
| 你的 Mac | `a123456@macbook-pro-3` | 账号名是 `a123456`,不是 fendada |

> 每台机器给你装哪一套,写在 `nixos/hosts/<机器名>/default.nix` 里你名字那一段。
> 想加减(比如想在 tank 上也用完整版),找 hank 改。

---

## 2. 第一次设置(每台机器只做一次)

### 服务器上(h610 / shanghai / tank)

机器本身已经是 NixOS 了,`nix` 和 `home-manager` 都现成的,只要把仓库弄下来:

```bash
git clone git@github.com:imdomestic/nix-config ~/.config/nix-config
cd ~/.config/nix-config
home-manager switch -b backup --flake .#你的配置名
```

配置名见上面第 1 节的表(比如 `kenneth@h610`)。跑完重开一个终端。
之后就有 `just` 了(如果你那台装了完整版),日常改用第 3 节的短命令。

> 需要你的 ssh key 在 GitHub 上、并且有 `imdomestic` 的读权限。
> 报 `Permission denied (publickey)` 就是这个,找 hank。

### fendada 的 Mac 上

Mac 上 Nix 不是自带的,先装(这一步要输密码,是唯一一次需要管理员权限的地方):

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

**装完关掉终端重开一个**,然后:

```bash
git clone git@github.com:imdomestic/nix-config ~/.config/nix-config
cd ~/.config/nix-config
nix run github:nix-community/home-manager/release-26.05 -- \
  switch -b backup --flake .#a123456@macbook-pro-3
```

第一次要用 `nix run` 是因为 `home-manager` 这个命令本身也是它装的 —— 先有鸡还是先有蛋。
装完之后,以后直接 `home-manager switch ...` 就行。

---

## 3. 日常:三步走

```bash
cd ~/.config/nix-config     # 仓库在这
$EDITOR home/users/你的名字/default.nix
```

改完,**先空跑看看会变什么**,确认没问题再真的应用。

### kenneth(三台服务器都一样)

```bash
just home-dry     # 空跑:只告诉你会变什么,不动任何东西
just home         # 真的应用
```

`just home` 会自动认出你是谁、在哪台机器上。

### fendada

h610 上和 kenneth 一样,`just home-dry` / `just home` 就行。

**shanghai、tank、和你的 Mac 上没有 `just`**,用完整命令(把 `#` 后面换成上表里对应的配置名):

```bash
# 在 shanghai 上
home-manager switch -b backup --flake .#fendada@shanghai --dry-run   # 空跑
home-manager switch -b backup --flake .#fendada@shanghai             # 应用

# 在你的 Mac 上
home-manager switch -b backup --flake .#a123456@macbook-pro-3
```

> `-b backup` 的意思是:如果 Nix 想接管一个已经存在的文件(比如你手写过的 `~/.zshrc`),
> 先把老的改名成 `.zshrc.backup` 而不是直接报错退出。第一次跑基本一定会用到。

跑完 **重开一个终端**(或 `exec zsh`),改动才会体现在你的 shell 里。

---

## 4. 最常干的三件事

### 装一个命令行工具

找到你文件里的 `home.packages`,加一行。比如 kenneth:

```nix
home = {
  packages = [
    pkgs.gnumake
    pkgs.nodejs
    pkgs.pnpm
    pkgs.subversion
    pkgs.ripgrep      # ← 加这行
  ];
```

包名怎么找:去 <https://search.nixos.org/packages>,或者命令行 `nix search nixpkgs ripgrep`。

> **fendada 注意**:你的文件是 `lib.mkMerge [ ... ]`,里面有三块。
> 第一块是**所有机器共用**;`lib.mkIf isDarwin { ... }` 那块**只在 Mac 上生效**;
> `lib.mkIf (!isDarwin) { ... }` 那块**只在服务器上生效**。
> 想让服务器也装个东西,就加到第三块里(它现在还没有 `home.packages`,自己新起一行
> `home.packages = with pkgs; [ ripgrep ];`)。

### 加一个 alias

```nix
programs.zsh.shellAliases = {
  gs = "git status";     # ← 加这行
};
```

kenneth 的 alias 已经有一大堆了,直接往 `shellAliases` 里加。

### 改 git 身份

```nix
programs.git.settings.user = {
  name = "你的名字";
  email = "你的邮箱";
};
```

---

## 5. 四条会咬人的规则

### ① 新文件不 `git add`,等于不存在

这条最坑,一定会撞上一次。这个仓库是通过 git 读文件的,**没被 git 跟踪的新文件,
Nix 完全看不见**。你会得到一个"文件不存在"的报错,但你明明看着它就在那。

```bash
git add home/users/你的名字/新文件.nix
```

改**已有**文件不用 add,直接改直接跑就行(只是会看到一句
`warning: Git tree has uncommitted changes`,这是正常的,不是错误)。

### ② 不要手改 `~/.zshrc` 这类文件

Nix 生成的配置文件是**只读软链**,指向 `/nix/store` 里面。你手动改了:

- 要么改不动(权限拒绝);
- 要么下次跑 `just home` 直接被覆盖回去。

想改什么,永远回到 `home/users/你的名字/default.nix` 里改。

### ③ 不要跑 `just switch`

那是**整台机器**的系统重建,是 hank 的活,你也没权限。你只需要 `just home`。

### ④ 装东西不要用 `nix-env -i` / `nix profile install`

那样装的东西不在配置里,换台机器就没了,而且迟早和 home-manager 打架。
一切都写进 `home.packages`。

---

## 6. 出问题了怎么办

### 报错看不懂

Nix 的报错又臭又长,但**真正的原因基本都在最下面几行**,上面那一大坨是调用栈。
先只看结尾:

```bash
just home 2>&1 | tail -20          # 有 just 的机器
home-manager switch -b backup --flake .#你的配置名 2>&1 | tail -20
```

常见的几种:

| 报错里有 | 意思 |
| --- | --- |
| `attribute 'xxx' missing` | 包名拼错了,或者这个包在你这个平台上没有 |
| `path ... does not exist` | 新文件忘了 `git add`(见规则 ①) |
| `Existing file ... would be clobbered` | 加上 `-b backup` 再跑 |
| `Permission denied (publickey)` | 求值时要拉一个私有仓库,你的 ssh key 没权限 —— 找 hank |
| `error: syntax error, unexpected ...` | Nix 语法写错了,通常是少了个 `;` 或括号没配对 |

> Nix 里**每一行结尾都要分号**,`{ }` 是属性集不是代码块。少分号是新手第一大错因。

### 想撤销刚才那次改动

最简单:把配置改回去,再跑一次 `just home`。

如果你不记得改了什么,可以直接跳回上一个版本:

```bash
home-manager generations
# 输出类似:
#   2026-08-05 14:32 : id 43 -> /nix/store/abc...-home-manager-generation
#   2026-08-05 11:07 : id 42 -> /nix/store/xyz...-home-manager-generation

/nix/store/xyz...-home-manager-generation/activate   # 跑上一代的 activate,就回去了
```

回滚是**瞬间**的,不需要重新构建 —— 老版本还完整躺在 `/nix/store` 里。
这也是 Nix 最大的好处:你怎么折腾都能一秒退回去。

### 占磁盘

旧的 generation 会一直留着(这正是能一秒回滚的原因)。清掉一个月以前的自己那份:

```bash
home-manager expire-generations "-30 days"
```

这只是松开你自己的引用,磁盘不会立刻变多 —— 真正删文件的那一步(`nix store gc`)
会影响整台机器上所有人,**在服务器上别自己跑,告诉 hank 就行**。
你自己的 Mac 上随便跑。

---

## 7. 把改动交上去

你的改动只存在于你这台机器的本地 checkout 里。要让它在**别的机器上**也生效,
或者别弄丢,得提交:

```bash
git add -A
git commit -m "kenneth: 加上 ripgrep"
git pull --rebase      # 先把别人的改动拉下来
git push
```

然后在其他机器上 `git pull` 再 `just home`。

> 能不能直接 push 到 main,问 hank。不能的话就开个分支发 PR。
> **只改你自己 `home/users/你的名字/` 下面的东西**,别的目录动之前先问一声。

---

## 8. 名词对照表

看报错和文档时会遇到:

| 词 | 人话 |
| --- | --- |
| **flake** | 这整个仓库。`.#kenneth@h610` 意思是"这个仓库里叫 `kenneth@h610` 的那份配置" |
| **derivation** | 一份"怎么构建某个东西"的配方。报错里的 `.drv` 就是它 |
| **/nix/store** | 所有软件和配置文件真正待的地方,只读,按内容哈希命名 |
| **generation** | 你的 home 的一个历史版本。每跑一次 `just home` 就多一代 |
| **activate** | "把某一代真正装到我的家目录里"的那个动作 |
| **home-manager** | 管你账号那一层的工具。`just home` 底下跑的就是它 |
| **NixOS / nix-darwin** | 管整台机器那一层。跟你没关系 |

---

## 9. 还想深入

- 这个仓库的整体结构:根目录 `README.md`
- Home Manager 所有能配的选项:<https://nix-community.github.io/home-manager/options.xhtml>
  (**强烈建议**先在这里搜一下,基本你想配的东西都有现成选项,不用手写配置文件)
- 找包:<https://search.nixos.org/packages>
