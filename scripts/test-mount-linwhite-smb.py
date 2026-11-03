#!/usr/bin/env python3
"""Offline regression tests; never mount/unmount a volume or access Keychain."""

import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location(
    "mount_linwhite_smb", Path(__file__).with_name("mount-linwhite-smb.py")
)
smb = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = smb
spec.loader.exec_module(smb)

TARGET = Path("/Volumes/seraph-linwhite")
GOOD = smb.Mount(TARGET, "//linwhite@seraph/seraph-linwhite", "smbfs")
OTHER = smb.Mount(Path(str(TARGET) + "-1"), GOOD.source, "smbfs")


class MountTests(unittest.TestCase):
    def test_mount_identity(self):
        for source in (GOOD.source, "//linwhite@seraph.inner.imdomestic.com/seraph-linwhite"):
            self.assertTrue(smb.Mount(TARGET, source, "smbfs").matches("seraph", "seraph-linwhite"))
        for source in ("//guest@seraph/seraph-linwhite", "//linwhite@evil/seraph-linwhite", "//linwhite@seraph/other"):
            self.assertFalse(smb.Mount(TARGET, source, "smbfs").matches("seraph", "seraph-linwhite"))
        self.assertFalse(smb.Mount(TARGET, GOOD.source, "apfs").matches("seraph", "seraph-linwhite"))

    def test_mount_table_parsing(self):
        output = SimpleNamespace(stdout=(
            "/dev/disk3s1 on / (apfs, sealed, local)\n"
            "//linwhite@seraph/seraph-linwhite on /Volumes/seraph-linwhite (smbfs, nodev)\n"
            "//guest@host/share on /Volumes/a\\040b (smbfs, nodev)\n"
        ))
        with patch.object(smb.subprocess, "run", return_value=output):
            mounts = smb.mount_table()
        self.assertEqual(mounts[1], GOOD)
        self.assertEqual(mounts[2].path, Path("/Volumes/a b"))

    def test_existing_mount_is_found_without_statting_it(self):
        self.assertTrue(smb.locate([GOOD], "seraph", "seraph-linwhite", TARGET))
        self.assertFalse(smb.locate([], "seraph", "seraph-linwhite", TARGET))

    def test_suffix_mount_blocks_duplicate_including_when_target_also_exists(self):
        for mounts in ([OTHER], [GOOD, OTHER]):
            with self.subTest(mounts=mounts), self.assertRaisesRegex(RuntimeError, "手动迁回"):
                smb.locate(mounts, "seraph", "seraph-linwhite", TARGET)

    def test_foreign_mount_at_target_blocks_recovery(self):
        foreign = smb.Mount(TARGET, "//guest@seraph/seraph-linwhite", "smbfs")
        with self.assertRaisesRegex(RuntimeError, "其他卷"):
            smb.locate([foreign], "seraph", "seraph-linwhite", TARGET)

    def test_empty_directory_is_reused_not_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "mount"
            target.mkdir(mode=0o700)
            inode = target.stat().st_ino
            smb.prepare_mountpoint(target)
            self.assertEqual(target.stat().st_ino, inode)

    def test_netfs_0111_directory_is_repaired(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "mount"
            target.mkdir(mode=0o111)
            smb.prepare_mountpoint(target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_nonempty_directory_is_not_hidden_or_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "keep").write_text("important")
            with self.assertRaisesRegex(RuntimeError, "非空"):
                smb.prepare_mountpoint(target)
            self.assertEqual((target / "keep").read_text(), "important")

    def test_nonempty_0111_directory_keeps_original_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "mount"
            target.mkdir()
            (target / "keep").write_text("important")
            target.chmod(0o111)
            try:
                with self.assertRaisesRegex(RuntimeError, "非空"):
                    smb.prepare_mountpoint(target)
                self.assertEqual(target.stat().st_mode & 0o777, 0o111)
            finally:
                target.chmod(0o700)
            self.assertEqual((target / "keep").read_text(), "important")

    def test_symlink_and_world_writable_directory_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "mount"
            target.symlink_to(Path(directory), target_is_directory=True)
            with self.assertRaises(RuntimeError):
                smb.prepare_mountpoint(target)
            target.unlink()
            target.mkdir()
            target.chmod(0o777)
            with self.assertRaises(RuntimeError):
                smb.prepare_mountpoint(target)

    def test_foreign_owner_is_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(smb.os, "getuid", return_value=-1):
            with self.assertRaises(RuntimeError):
                smb.prepare_mountpoint(Path(directory))

    def test_missing_directory_is_not_created_by_user_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "missing"
            with self.assertRaises(FileNotFoundError):
                smb.prepare_mountpoint(target)
            self.assertFalse(target.exists())

    def test_shortcut_conflict_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            shortcut = Path(directory) / "shortcut"
            shortcut.write_text("keep")
            with self.assertRaises(RuntimeError):
                smb.validate_shortcut(shortcut, TARGET)
            self.assertEqual(shortcut.read_text(), "keep")
            shortcut.unlink()
            shortcut.symlink_to("/somewhere-else")
            with self.assertRaises(RuntimeError):
                smb.validate_shortcut(shortcut, TARGET)
            self.assertEqual(shortcut.readlink(), Path("/somewhere-else"))

    def test_probe_is_bounded(self):
        with patch.object(smb.subprocess, "run", side_effect=subprocess.TimeoutExpired("probe", 8)):
            self.assertFalse(smb.share_ready(TARGET))
            self.assertFalse(smb.server_ready("seraph"))

    def recover(self, mounts, state, network=True, io=True, run=None):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(smb, "mount_table", side_effect=mounts), \
                patch.object(smb, "server_ready", side_effect=network if isinstance(network, list) else None, return_value=network), \
                patch.object(smb, "share_ready", return_value=io), \
                patch.object(smb, "prepare_mountpoint") as prepare, \
                patch.object(smb.time, "sleep"), \
                patch.object(smb.subprocess, "run", side_effect=run) as child:
            shortcut = Path(directory) / "Servers/seraph"
            result = smb.recover("seraph", "seraph-linwhite", shortcut, state)
            linked = shortcut.is_symlink() and shortcut.readlink() == TARGET
            return result[0], child.call_count, prepare.call_count, linked

    def test_healthy_mount_is_reused_and_original_shortcut_created(self):
        state = {"absent_since": 0}
        self.assertEqual(self.recover([[GOOD]], state), ("healthy", 0, 0, True))
        self.assertNotIn("absent_since", state)

    def test_network_down_does_not_mount_or_touch_directory(self):
        self.assertEqual(self.recover([[]], {}, network=False), ("waiting-network", 0, 0, False))

    def test_stale_registered_mount_is_not_replaced_or_unmounted(self):
        self.assertEqual(self.recover([[GOOD]], {}, io=False), ("waiting-session", 0, 0, False))

    def test_first_absence_waits_for_system_reconnect(self):
        self.assertEqual(self.recover([[]], {}), ("waiting-remount", 0, 0, False))

    def test_unstable_network_defers_mount(self):
        self.assertEqual(self.recover([[]], {"absent_since": 0}, network=[True, False]), ("waiting-network", 0, 0, False))

    def test_system_mount_appearing_during_grace_is_reused(self):
        self.assertEqual(self.recover([[], [GOOD], [GOOD]], {"absent_since": 0}), ("healthy", 0, 0, True))

    def test_successful_remount_restores_fixed_path(self):
        result = SimpleNamespace(returncode=0)
        self.assertEqual(self.recover([[], [], [GOOD]], {"absent_since": 0}, run=[result]), ("healthy", 1, 1, True))

    def test_netfs_timeout_waits_and_rescans_next_time(self):
        state = {"absent_since": 0}
        result = self.recover([[], []], state, run=subprocess.TimeoutExpired("mount", 45))
        self.assertEqual(result, ("waiting-netfs", 1, 1, False))
        self.assertGreater(state["absent_since"], 0)

    def test_failed_mount_resets_grace_without_creating_shortcut(self):
        state = {"absent_since": 0}
        result = SimpleNamespace(returncode=1, stderr="NetFS failed")
        with self.assertRaisesRegex(RuntimeError, "NetFS failed"):
            self.recover([[], []], state, run=[result])
        self.assertGreater(state["absent_since"], 0)

    def test_mount_worker_passes_exact_mount_directory_option(self):
        netfs, security, url = MagicMock(), MagicMock(), MagicMock()
        security.errSecSuccess = 0
        security.SecItemCopyMatching.return_value = (0, b"not-a-real-password")
        netfs.NetFSMountURLSync.return_value = (0, [str(TARGET)])
        foundation = SimpleNamespace(NSURL=url)
        with patch.dict(sys.modules, {"NetFS": netfs, "Security": security, "Foundation": foundation}), \
                patch.object(smb, "mount_table", side_effect=[[], [GOOD]]), \
                patch.object(smb, "prepare_mountpoint"):
            smb.mount_worker("seraph", "seraph-linwhite", TARGET)
        args = netfs.NetFSMountURLSync.call_args.args
        self.assertEqual(args[1], url.fileURLWithPath_.return_value)
        url.fileURLWithPath_.assert_called_once_with(str(TARGET))
        self.assertEqual(args[5], {netfs.kNetFSMountAtMountDirKey: True})
        self.assertNotIn(netfs.kNetFSSoftMountKey, args[5])

    def test_eexist_requires_verified_mount_not_blind_success(self):
        netfs, security = MagicMock(), MagicMock()
        security.errSecSuccess = 0
        security.SecItemCopyMatching.return_value = (0, b"not-a-real-password")
        netfs.NetFSMountURLSync.return_value = (errno.EEXIST, None)
        with patch.dict(sys.modules, {"NetFS": netfs, "Security": security, "Foundation": MagicMock()}), \
                patch.object(smb, "mount_table", side_effect=[[], []]), \
                patch.object(smb, "prepare_mountpoint"):
            with self.assertRaisesRegex(RuntimeError, "未恢复原路径"):
                smb.mount_worker("seraph", "seraph-linwhite", TARGET)

    def test_lock_serializes_same_share(self):
        with tempfile.TemporaryDirectory() as directory:
            with smb.locked_state(Path(directory), "seraph"):
                with self.assertRaises(BlockingIOError):
                    with smb.locked_state(Path(directory), "seraph"):
                        self.fail("concurrent lock acquired")
                with smb.locked_state(Path(directory), "encore"):
                    pass

    def test_logs_only_state_transitions_and_persists_check_time(self):
        with tempfile.TemporaryDirectory() as directory, patch("builtins.print") as output:
            path, state = Path(directory) / "state.json", {}
            smb.report(path, state, "seraph", "healthy", "ready")
            smb.report(path, state, "seraph", "healthy", "ready")
            output.assert_called_once()
            smb.report(path, state, "seraph", "waiting-network", "offline")
            self.assertEqual(output.call_count, 2)
            self.assertEqual(json.loads(path.read_text())["status"], "waiting-network")
            self.assertIn("checked_at", json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
