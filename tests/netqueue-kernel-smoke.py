#!/usr/bin/env python3
"""Run the NFQUEUE proof only in fresh user+network namespaces, never a VM.

Run beneath run-memory-guard.py. No detached process or host nft rule is used.
The Rust probe independently checks the mapping and interfaces before nft.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    args = parser.parse_args()
    probe = args.probe.resolve(strict=True)
    commands = {name: shutil.which(name) for name in ('unshare', 'ip', 'nft')}
    if not all(commands.values()):
        raise SystemExit('unshare, ip and nft are required; no host fallback')
    env = dict(os.environ,
               CELLWARD_PROBE_OUTER_NETNS=os.readlink('/proc/self/ns/net'),
               CELLWARD_PROBE_NFT=commands['nft'],
               CELLWARD_PROBE_IP=commands['ip'])
    for family in ('ipv4', 'ipv6'):
        print(f'Checking {family} in a new disposable namespace', flush=True)
        result = subprocess.run([commands['unshare'], '--user', '--map-root-user',
                                 '--net', '--', str(probe), family], env=env,
                                timeout=20, check=False)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
