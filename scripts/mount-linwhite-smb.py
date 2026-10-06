import argparse
from pathlib import Path
import sys

from Foundation import NSURL
import NetFS
import Security


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--share")
    parser.add_argument("--shortcut", type=Path)
    parser.add_argument("--provision", action="store_true")
    args = parser.parse_args()
    query = {
        Security.kSecClass: Security.kSecClassInternetPassword,
        Security.kSecAttrServer: args.server,
        Security.kSecAttrAccount: "linwhite",
        Security.kSecAttrProtocol: Security.kSecAttrProtocolSMB,
    }
    if args.provision:
        password = sys.stdin.buffer.read().strip()
        if not password:
            raise ValueError("SMB 凭据为空")
        status = Security.SecItemUpdate(query, {Security.kSecValueData: password})
        if status == Security.errSecItemNotFound:
            status, _ = Security.SecItemAdd(
                {**query, Security.kSecValueData: password}, None
            )
        if status != Security.errSecSuccess:
            raise RuntimeError(f"保存 {args.server} 钥匙串凭据失败：{status}")
        print(f"已保存 {args.server} 的 linwhite SMB 凭据")
        return
    if args.share is None or args.shortcut is None:
        parser.error("挂载需要 --share 和 --shortcut")
    mountpoint = Path("/Volumes") / args.share
    if args.shortcut.is_symlink():
        if args.shortcut.readlink() != mountpoint:
            raise RuntimeError(f"挂载快捷入口与配置不符：{args.shortcut}")
    elif args.shortcut.exists():
        raise RuntimeError(f"挂载快捷入口被已有文件占用：{args.shortcut}")
    if not mountpoint.is_mount():
        status, data = Security.SecItemCopyMatching(
            {
                **query,
                Security.kSecReturnData: True,
                Security.kSecMatchLimit: Security.kSecMatchLimitOne,
                Security.kSecUseAuthenticationUI: Security.kSecUseAuthenticationUIFail,
            },
            None,
        )
        if status != Security.errSecSuccess:
            raise RuntimeError(f"读取 {args.server} 钥匙串凭据失败：{status}")
        status, mountpoints = NetFS.NetFSMountURLSync(
            NSURL.URLWithString_(f"smb://linwhite@{args.server}/{args.share}"),
            None,
            "linwhite",
            bytes(data).decode(),
            {NetFS.kNAUIOptionKey: NetFS.kNAUIOptionNoUI},
            {},
            None,
        )
        if status != 0:
            raise RuntimeError(f"挂载 {args.server} 失败：{status}")
        if list(mountpoints) != [str(mountpoint)] or not mountpoint.is_mount():
            raise RuntimeError(f"挂载目录与配置不符：{mountpoints}")
    mounted_url = NetFS.NetFSCopyURLForRemountingVolume(
        NSURL.fileURLWithPath_(str(mountpoint))
    )
    if (
        mounted_url is None
        or mounted_url.host() != args.server
        or mounted_url.path() != f"/{args.share}"
        or mounted_url.user() != "linwhite"
    ):
        raise RuntimeError(f"挂载目录与配置不符：{mountpoint}")
    args.shortcut.parent.mkdir(parents=True, exist_ok=True)
    if not args.shortcut.is_symlink():
        args.shortcut.symlink_to(mountpoint, target_is_directory=True)
    print(f"{args.server} 已挂载到 {mountpoint}，快捷入口为 {args.shortcut}")


if __name__ == "__main__":
    main()
