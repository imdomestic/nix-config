# 本机练习用的 PostgreSQL:以当前用户身份跑在 launchd 用户 agent 里,数据在
# ~/.local/share/postgresql/<大版本>,只听 localhost,本机连接一律 trust。
#
# 不用 nix-darwin 的 services.postgresql:那是 system 模块(改一次要 root),
# 默认 dataDir 在 /var/lib 下而它的用户 agent 没权限建,ensureDatabases /
# ensureUsers 也没实现。Home Manager 没有 postgres 模块,所以自己起 agent。
#
# 停:`pg_ctl stop`(KeepAlive 只在崩溃时拉起,正常退出后保持停着)
# 起:`launchctl kickstart gui/$UID/org.nix-community.home.postgresql`
# 日志:~/Library/Logs/postgresql.log
{
  config,
  pkgs,
  ...
}: let
  # 换大版本不会自动迁移:dataDir 带版本号,新版本会 initdb 一个空库,
  # 旧数据要自己 pg_dumpall / pg_upgrade 过去。
  postgresql = pkgs.postgresql_18;
  dataDir = "${config.xdg.dataHome}/postgresql/${postgresql.psqlSchema}";

  # launchd 下没有 LANG,不指定的话 initdb 会建成 SQL_ASCII。macOS 的 libc
  # 没有 C.UTF-8,所以 libc 那层用 C,排序和大小写走 builtin provider。
  initdbArgs = [
    "--auth=trust"
    "--encoding=UTF8"
    "--locale=C"
    "--locale-provider=builtin"
    "--builtin-locale=C.UTF-8"
  ];

  # initdb 的超级用户就是当前用户;再补上同名库(裸 `psql` 默认连它)和
  # 教程里常见的 postgres 角色。单用户模式不需要 server 先起来。
  bootstrapSql = pkgs.writeText "postgresql-bootstrap.sql" ''
    CREATE DATABASE "${config.home.username}";
    CREATE ROLE postgres SUPERUSER LOGIN;
  '';

  start = pkgs.writeShellScript "postgresql-start" ''
    set -eu
    if [ ! -e "${dataDir}/PG_VERSION" ]; then
      ${postgresql}/bin/initdb -D "${dataDir}" ${toString initdbArgs}
      ${postgresql}/bin/postgres --single -D "${dataDir}" postgres < ${bootstrapSql}
    fi
    exec ${postgresql}/bin/postgres -D "${dataDir}"
  '';
in {
  home.packages = [postgresql];

  # 让 pg_ctl / pg_controldata 不带 -D 就能用。
  home.sessionVariables.PGDATA = dataDir;

  launchd.agents.postgresql = {
    enable = true;
    config = {
      ProgramArguments = ["${start}"];
      RunAtLoad = true;
      KeepAlive.SuccessfulExit = false;
      StandardOutPath = "${config.home.homeDirectory}/Library/Logs/postgresql.log";
      StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/postgresql.log";
    };
  };
}
