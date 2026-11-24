# maxx 的数据库备份

maxx 的库在它自己的 Postgres 集群里（`maxx-postgres.service`，见 max 仓库
`docs/design/config.md` 的 NixOS 一节）。备份配置在 `hosts/tank/maxx-backup.nix`。

- **每晚 04:20**，tank 上的 `restic-backups-maxx` 以集群用户 `maxx-postgres` 跑
  `pg_dump`，经 sftp 存进 h610 的 `/var/lib/restic/tank-maxx`。restic 把它切块去重、
  压缩、加密，每晚只多出变了的那部分。保留每天 14 份、每周 8 份、每月 12 份，备份完
  `restic check` 一次。
- **每周日 05:50**，`maxx-restore-check` 把最新一份还原进 `/var/tmp` 里的临时集群，
  要求迁移记录不为空、最新的消息不超过 48 小时。
- 两个任务失败都会触发 `SystemdUnitFailed` 告警。
- **仓库密码**在 sops `secrets/hosts/tank-max.yaml` 的 `maxx/restic-password`。
  丢了它仓库就打不开。
- 以 root 写 h610 的原因见 [decisions.md](../decisions.md#maxx-backup-as-root)。

## 常用

```sh
restic-maxx snapshots                    # 有哪些快照
systemctl start restic-backups-maxx      # 立刻备份一次，比如部署前
journalctl -u restic-backups-maxx -n 30
systemctl start maxx-restore-check; journalctl -u maxx-restore-check -n 5
maxx-psql                                # 以超级用户进 maxx 的库
```

## 部署前

部署要跑迁移、或者要手动执行 SQL 时，先 `systemctl start restic-backups-maxx`，
等它跑完再停 maxx。

## 还原

maxx 要先停下，`maxx.socket` 也要停：只停 service 的话，VM 的下一次调用会把
它重新拉起来。

```sh
systemctl stop maxx.socket maxx.service
restic-maxx snapshots                    # 挑一份；latest 是最新的
maxx-psql --dbname=postgres -c 'drop database maxx' -c 'create database maxx owner maxx'
restic-maxx dump latest /maxx.sql | maxx-psql -v ON_ERROR_STOP=1 --quiet > /dev/null
systemctl start maxx.socket maxx.service
```
