#!/usr/bin/env python3
"""Isolated input-filter acceptance. Run as root: unshare -n python3 <script>."""
import os
import socket
import subprocess as sp
import sys


def run(*args, **kwargs):
    return sp.run(args, check=True, **kwargs)


assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Run inside unshare -n, never in the host network namespace'
run('ip', 'link', 'set', 'lo', 'up')
peer = sp.Popen(['unshare', '-n', 'sleep', '120'])
try:
    import time
    time.sleep(.2)
    prefix = ['nsenter', '-t', str(peer.pid), '-n']
    run(*prefix, 'ip', 'link', 'set', 'lo', 'up')
    for interface, remote, v4, v6 in [('wan0','wanpeer','192.0.2','fd00:1'), ('tailscale0','tspeer','100.64.254','fd00:2')]:
        run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', remote)
        run('ip', 'link', 'set', remote, 'netns', str(peer.pid))
        run('ip', 'addr', 'add', v4+'.1/24', 'dev', interface)
        run('ip', '-6', 'addr', 'add', v6+'::1/64', 'dev', interface, 'nodad')
        run('ip', 'link', 'set', interface, 'up')
        run(*prefix, 'ip', 'addr', 'add', v4+'.2/24', 'dev', remote)
        run(*prefix, 'ip', '-6', 'addr', 'add', v6+'::2/64', 'dev', remote, 'nodad')
        run(*prefix, 'ip', 'link', 'set', remote, 'up')
    run('nft','-f','-',input='''table inet tailnet_web_test {
      chain input {
        type filter hook input priority -10; policy accept;
        iifname != { "lo", "tailscale0" } tcp dport { 80, 443, 9090 } counter drop
      }
    }''',text=True)
    listeners=[]
    for family, address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
        for port in [80,443,9090,8443]:
            sock=socket.socket(family)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((address,port));sock.listen(20);listeners.append(sock)
    count=0
    for address, allowed in [('192.0.2.1',False),('fd00:1::1',False),('100.64.254.1',True),('fd00:2::1',True)]:
        for port in [80,443,9090,8443]:
            code='import socket,sys\ns=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=.5)\ns.close()'
            result=sp.run(prefix+[sys.executable,'-c',code,address,str(port)],stdout=sp.DEVNULL,stderr=sp.DEVNULL)
            expected=allowed or port==8443
            assert (result.returncode==0)==expected,(address,port,result.returncode)
            count+=1
    for port in [80,443,9090,8443]:
        with socket.create_connection(('127.0.0.1',port),timeout=1): pass
        count+=1
    print(f'PASS {count} isolated IPv4/IPv6 input checks: private ports restricted, 8443 reachable, loopback allowed')
finally:
    peer.terminate();peer.wait()
