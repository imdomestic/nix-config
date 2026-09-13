"""Resolve a local tailnet name; adapt only IP-only native application fields."""
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def resolve_local(name):
    addresses = {entry[4][0] for entry in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)}
    interfaces = json.loads(subprocess.check_output([os.environ['TAILSCALE_BIND_IP'], '-j', '-4', 'address', 'show', 'dev', 'tailscale0']))
    local = {entry['local'] for interface in interfaces for entry in interface['addr_info']}
    matches = addresses & local
    if addresses != matches or len(matches) != 1 or not all(ipaddress.ip_address(address) in ipaddress.ip_network('100.64.0.0/10') for address in addresses):
        raise ValueError('MagicDNS must resolve to this machine on tailscale0')
    return matches.pop()


def wait_local(name):
    for attempt in range(60):
        try:
            return resolve_local(name)
        except (OSError, ValueError, subprocess.CalledProcessError):
            if attempt == 59:
                raise
            time.sleep(2)


def main():
    kind, *args = sys.argv[1:]
    if kind == 'check':
        wait_local(args[0])
        return
    program, *arguments = args
    if kind == 'json':
        index = arguments.index('--config') + 1
        data = json.loads(Path(arguments[index]).read_text())
        name, port = data['listen'].rsplit(':', 1)
        if name not in ('127.0.0.1', '[::1]'):
            data['listen'] = f'{wait_local(name)}:{port}'
        fd, path = tempfile.mkstemp(prefix='tailscale-bind-', suffix='.json', dir=os.environ['RUNTIME_DIRECTORY'])
        with os.fdopen(fd, 'w') as output:
            json.dump(data, output)
        arguments[index] = path
    elif kind == 'headplane':
        os.environ['HEADPLANE_SERVER__HOST'] = wait_local(os.environ['TAILSCALE_BIND_NAME'])
    elif kind == 'alertmanager':
        # memberlist requires a numeric advertised address; peers remain DNS names.
        name = os.environ['TAILSCALE_BIND_NAME']
        if '--cluster.listen-address=' not in arguments:
            arguments += [f'--cluster.advertise-address={wait_local(name)}:9094']
    else:
        raise ValueError(f'Unknown adapter {kind}')
    os.execv(program, [program, *arguments])


if __name__ == '__main__':
    main()
