#!/usr/bin/env python3
"""An authentic live net namespace with host PID namespace must be refused."""
import argparse,os,subprocess,sys,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--unshare',required=True);a=p.parse_args()
root=Path(tempfile.mkdtemp(prefix='cellward-old-pidns-'));print(f'Artifacts: {root}',flush=True)
helper=subprocess.Popen([a.unshare,'--user','--map-current-user','--net','--',sys.executable,'-c','import os,time; print(os.getpid(),flush=True);time.sleep(60)'],stdout=subprocess.PIPE,text=True)
try:
 pid=int(helper.stdout.readline());assert os.readlink(f'/proc/{pid}/ns/pid')==os.readlink('/proc/self/ns/pid');assert os.readlink(f'/proc/{pid}/ns/net')!=os.readlink('/proc/self/ns/net')
 instance='main:offline';key=0xcbf29ce484222325
 for byte in instance.encode():key=((key^byte)*0x100000001b3)&((1<<64)-1)
 d=root/'.local/state/vpn-zones/.instances'/f'i-{key:016x}';d.mkdir(parents=True)
 stat=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split();stamp=f'{stat[19]} {Path("/proc/sys/kernel/random/boot_id").read_text().strip()}'
 for name,value in [('id',instance),('instance.pid',str(pid)),('instance.start',stamp),('ready',''),('network','offline')]: (d/name).write_text(value)
 marker=root/'must-not-run';env=dict(os.environ,HOME=str(root))
 r=subprocess.run([a.core,'container-enter','--instance',instance,'--network','offline','--',sys.executable,'-c',f'from pathlib import Path;Path({str(marker)!r}).touch()'],env=env,capture_output=True,text=True,timeout=10)
 (root/'result.log').write_text(r.stdout+r.stderr)
 assert r.returncode!=0 and 'своего пространства pid у него нет' in r.stderr,(r.returncode,r.stdout,r.stderr)
 assert not marker.exists()
 print('PASS: old instance with host PID namespace refused before entering; command not executed')
finally:
 helper.terminate();helper.wait(timeout=5)
