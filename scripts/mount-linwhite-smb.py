"""Keep a Keychain-backed SMB share at a fixed mountpoint.

See docs/incidents.md#smb-fixed-mountpoint for recovery constraints.
"""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True)
class Mount:
    path: Path
    source: str
    filesystem: str

    def matches(self, server, share):
        if self.filesystem != "smbfs":
            return False
        url = urlsplit("smb:" + self.source)
        return (
            url.hostname in {server, f"{server}.inner.imdomestic.com"}
            and unquote(url.path) == f"/{share}"
            and unquote(url.username or "") == "linwhite"
        )


def mount_table():
    result = subprocess.run(
        ["/sbin/mount"], capture_output=True, text=True, check=True, timeout=10
    )
    mounts = []
    for line in result.stdout.splitlines():
        source_path, options = line.rsplit(" (", 1)
        source, path = source_path.rsplit(" on ", 1)
        path = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), path)
        mounts.append(Mount(Path(path), source, options.split(",")[0].rstrip(")")))
    return mounts


def locate(mounts, server, share, target):
    at_target = [m for m in mounts if m.path == target]
    if any(not m.matches(server, share) for m in at_target):
        raise RuntimeError(f"原路径被其他卷占用：{target}；不卸载、不覆盖")
    matching = [m for m in mounts if m.matches(server, share)]
    if any(m.path != target for m in matching):
        paths = ", ".join(str(m.path) for m in matching)
        raise RuntimeError(f"共享已挂载于 {paths}；需在关闭文件后手动迁回 {target}")
    return bool(at_target)


def validate_shortcut(shortcut, target):
    if shortcut.is_symlink():
        if shortcut.readlink() != target:
            raise RuntimeError(f"快捷入口指向其他路径：{shortcut}；不覆盖")
    elif shortcut.exists():
        raise RuntimeError(f"快捷入口被已有文件占用：{shortcut}")


def prepare_mountpoint(target):
    # /Volumes belongs to root; nix-darwin creates missing directories at activation.
    info = target.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError(f"挂载目录不是当前用户拥有的真实目录：{target}")
    if getattr(info, "st_flags", 0) or info.st_mode & 0o022:
        raise RuntimeError(f"挂载目录有文件标志或允许他人写入：{target}")
    # NetFS can leave an owned 0111 directory after unmounting. Never remove it.
    repaired = stat.S_IMODE(info.st_mode) == 0o111
    if repaired:
        target.chmod(0o700)
    try:
        with os.scandir(target) as entries:
            if next(entries, None) is not None:
                raise RuntimeError(f"原挂载目录非空：{target}；不覆盖、不删除")
    except Exception:
        if repaired:
            target.chmod(0o111)
        raise


def probe(command, timeout):
    try:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def server_ready(server):
    # Bound DNS resolution as well as connect(), without logging any credentials.
    return probe([
        sys.executable, "-c",
        "import socket,sys; socket.create_connection((sys.argv[1],445),timeout=4).close()",
        server,
    ], 8)


def share_ready(target):
    # A mount-table entry alone is not proof that SMB I/O has recovered.
    return probe(["/bin/ls", "-f", str(target)], 8)


def keychain_query(server):
    import Security

    return {
        Security.kSecClass: Security.kSecClassInternetPassword,
        Security.kSecAttrServer: server,
        Security.kSecAttrAccount: "linwhite",
        Security.kSecAttrProtocol: Security.kSecAttrProtocolSMB,
    }


def provision(server):
    import Security

    query = keychain_query(server)
    password = sys.stdin.buffer.read().strip()
    if not password:
        raise ValueError("SMB 凭据为空")
    status = Security.SecItemUpdate(query, {Security.kSecValueData: password})
    if status == Security.errSecItemNotFound:
        status, _ = Security.SecItemAdd({**query, Security.kSecValueData: password}, None)
    if status != Security.errSecSuccess:
        raise RuntimeError(f"保存 {server} 钥匙串凭据失败：{status}")
    print(f"已保存 {server} 的 linwhite SMB 凭据", flush=True)


def mount_worker(server, share, target):
    from Foundation import NSURL
    import NetFS
    import Security

    status, data = Security.SecItemCopyMatching(
        {
            **keychain_query(server),
            Security.kSecReturnData: True,
            Security.kSecMatchLimit: Security.kSecMatchLimitOne,
            Security.kSecUseAuthenticationUI: Security.kSecUseAuthenticationUIFail,
        },
        None,
    )
    if status != Security.errSecSuccess:
        raise RuntimeError(f"读取 {server} 钥匙串凭据失败：{status}")
    # Recheck after Keychain access; Finder is not covered by our process lock.
    if locate(mount_table(), server, share, target):
        return
    prepare_mountpoint(target)
    status, paths = NetFS.NetFSMountURLSync(
        NSURL.URLWithString_(f"smb://linwhite@{server}/{share}"),
        NSURL.fileURLWithPath_(str(target)),
        "linwhite",
        bytes(data).decode(),
        {NetFS.kNAUIOptionKey: NetFS.kNAUIOptionNoUI},
        {NetFS.kNetFSMountAtMountDirKey: True},
        None,
    )
    if status not in (0, errno.EEXIST):
        detail = os.strerror(status) if status > 0 else "OSStatus"
        raise RuntimeError(f"NetFS 挂载失败：{status} ({detail})")
    if not locate(mount_table(), server, share, target):
        raise RuntimeError(f"NetFS 未恢复原路径：{target}；返回 {paths}")


def recover(server, share, shortcut, state):
    target = Path("/Volumes") / share
    validate_shortcut(shortcut, target)
    mounted = locate(mount_table(), server, share, target)
    if mounted:
        state.pop("absent_since", None)
    else:
        state.setdefault("absent_since", time.time())
    if not server_ready(server):
        return "waiting-network", "TCP 445 / DNS 尚未就绪；保留原路径，稍后重试"
    if mounted:
        if not share_ready(target):
            return "waiting-session", "原挂载仍登记但目录访问失败；等待系统重连，不强制卸载"
    else:
        # Give NetAuth/system reconnect a full interval before creating a new session.
        if time.time() - state["absent_since"] < 60:
            return "waiting-remount", "共享未登记；等待 60 秒，避免与系统重连竞争"
        time.sleep(3)
        if not server_ready(server):
            return "waiting-network", "网络尚未稳定；稍后重试"
        if not locate(mount_table(), server, share, target):
            prepare_mountpoint(target)
            try:
                result = subprocess.run(
                    [sys.executable, __file__, "--server", server, "--share", share,
                     "--mount-worker"], capture_output=True, text=True, timeout=45,
                )
            except subprocess.TimeoutExpired:
                state["absent_since"] = time.time()
                return "waiting-netfs", "NetFS 超过 45 秒；结果未知，下轮先重新扫描挂载表"
            if result.returncode:
                state["absent_since"] = time.time()
                raise RuntimeError(result.stderr.strip() or "挂载子进程失败")
        if not locate(mount_table(), server, share, target) or not share_ready(target):
            return "waiting-session", "挂载后目录访问未就绪；等待下轮检查"
        state.pop("absent_since", None)
    shortcut.parent.mkdir(parents=True, exist_ok=True)
    validate_shortcut(shortcut, target)
    if not shortcut.is_symlink():
        shortcut.symlink_to(target, target_is_directory=True)
    return "healthy", f"原路径可访问：{target}；快捷入口 {shortcut}"


@contextmanager
def locked_state(directory, server):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / f"{server}.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory / f"{server}.json"


def report(path, state, server, status, message):
    previous = (state.get("status"), state.get("message"))
    if previous != (status, message):
        stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        print(f"{stamp} {server} [{status}] {message}", flush=True)
    state.update(status=status, message=message, checked_at=time.time())
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, choices=["seraph", "encore"])
    parser.add_argument("--share")
    parser.add_argument("--shortcut", type=Path)
    parser.add_argument("--provision", action="store_true")
    parser.add_argument("--mount-worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.provision:
        provision(args.server)
        return 0
    if args.share != f"{args.server}-linwhite":
        parser.error("--share 必须是 <server>-linwhite")
    if args.mount_worker:
        mount_worker(args.server, args.share, Path("/Volumes") / args.share)
        return 0
    if args.shortcut is None:
        parser.error("挂载需要 --shortcut")
    directory = Path.home() / "Library/Application Support/linwhite-smb"
    try:
        with locked_state(directory, args.server) as path:
            state = json.loads(path.read_text()) if path.exists() else {}
            try:
                status, message = recover(args.server, args.share, args.shortcut, state)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                status, message = "error", str(exc)
            report(path, state, args.server, status, message)
            return 0 if status == "healthy" else 1
    except BlockingIOError:
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
