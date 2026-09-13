#!/usr/bin/env python3
"""Check that DNS migration cannot silently widen a service listener."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'nixos/modules/tailscale/resolve-bind.py'
spec = importlib.util.spec_from_file_location('resolve_bind', source)
bind = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bind)


class BindTests(unittest.TestCase):
    def resolve(self, dns, local):
        answers = [(2, 1, 6, '', (ip, 0)) for ip in dns]
        interfaces = json.dumps([{'addr_info': [{'local': ip} for ip in local]}]).encode()
        with patch.object(bind.socket, 'getaddrinfo', return_value=answers), patch.object(bind.subprocess, 'check_output', return_value=interfaces), patch.dict(os.environ, {'TAILSCALE_BIND_IP': '/test/ip'}):
            return bind.resolve_local('host.inner.example.com')

    def test_newly_allocated_address_is_used(self):
        self.assertEqual(self.resolve(['100.64.9.42'], ['100.64.9.42']), '100.64.9.42')

    def test_old_dns_after_address_change_is_rejected(self):
        with self.assertRaises(ValueError):
            self.resolve(['100.64.0.3'], ['100.64.9.42'])

    def test_foreign_or_wildcard_dns_is_rejected(self):
        for address in ['0.0.0.0', '127.0.0.1', '192.168.1.1', '203.0.113.1']:
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.resolve([address], [address])

    def test_mixed_local_and_remote_answers_are_rejected(self):
        with self.assertRaises(ValueError):
            self.resolve(['100.64.0.3', '100.64.0.4'], ['100.64.0.3'])

    def test_json_adapter_preserves_other_native_settings(self):
        original = {'listen': 'host.inner.example.com:9720', 'token_file': '/run/credentials/token', 'manageable_units': ['one.service']}
        with tempfile.TemporaryDirectory() as directory:
            source_config = Path(directory) / 'native.json'
            source_config.write_text(json.dumps(original))
            with patch.object(bind.sys, 'argv', ['adapter', 'json', '/bin/agent', '--config', str(source_config)]), patch.object(bind, 'wait_local', return_value='100.64.9.42'), patch.object(bind.os, 'execv') as execute, patch.dict(os.environ, {'RUNTIME_DIRECTORY': directory}):
                bind.main()
                args = execute.call_args.args[1]
                rendered = Path(args[2])
                expected = dict(original, listen='100.64.9.42:9720')
                self.assertEqual(json.loads(rendered.read_text()), expected)
                self.assertEqual(rendered.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(source_config.read_text()), original)

    def test_headplane_uses_native_environment_override(self):
        with patch.object(bind.sys, 'argv', ['adapter', 'headplane', '/bin/headplane']), patch.object(bind, 'wait_local', return_value='100.64.9.42'), patch.object(bind.os, 'execv'), patch.dict(os.environ, {'TAILSCALE_BIND_NAME': 'host.inner.example.com'}):
            bind.main()
            self.assertEqual(os.environ['HEADPLANE_SERVER__HOST'], '100.64.9.42')

    def test_alertmanager_advertises_current_address(self):
        with patch.object(bind.sys, 'argv', ['adapter', 'alertmanager', '/bin/alertmanager', '--cluster.peer=peer.inner.example.com:9094']), patch.object(bind, 'wait_local', return_value='100.64.9.42'), patch.object(bind.os, 'execv') as execute, patch.dict(os.environ, {'TAILSCALE_BIND_NAME': 'host.inner.example.com'}):
            bind.main()
            self.assertIn('--cluster.advertise-address=100.64.9.42:9094', execute.call_args.args[1])

    def test_disabled_cluster_does_not_require_an_advertised_address(self):
        with patch.object(bind.sys, 'argv', ['adapter', 'alertmanager', '/bin/alertmanager', '--cluster.listen-address=']), patch.object(bind, 'wait_local') as resolve, patch.object(bind.os, 'execv'), patch.dict(os.environ, {'TAILSCALE_BIND_NAME': 'host.inner.example.com'}):
            bind.main()
            resolve.assert_not_called()


if __name__ == '__main__':
    unittest.main()
