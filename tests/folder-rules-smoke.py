#!/usr/bin/env python3
"""Real nested mounts on synthetic data, never the user's home or desktop."""
import argparse, os, subprocess, sys, tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--core',required=True);p.add_argument('--bwrap',required=True);p.add_argument('--unshare',required=True);a=p.parse_args()
root=Path(tempfile.mkdtemp(prefix='cellward-folder-rules-'));print(f'Artifacts: {root}',flush=True)
home=root/'home';project=home/'Projects';shared=project/'shared';cache=shared/'cache';readonly=project/'read-only'
for d in (home,project,shared,cache,readonly):d.mkdir(parents=True,exist_ok=True)
for d in (project,shared,cache,readonly):(d/'original').write_text('host')
data=root/'layer';data.mkdir();runtime=root/'runtime';runtime.mkdir(mode=0o700)
policy=home/'.config/vpn-zones/containers/test';policy.mkdir(parents=True);(policy/'perms').write_text('')
env=dict(os.environ,HOME=str(home),XDG_RUNTIME_DIR=str(runtime));env.pop('WAYLAND_DISPLAY',None);env.pop('DISPLAY',None);env.pop('VPN_ZONE_EXPECT_PIDNS',None)
rules=[('overlay',project),('rw',shared),('overlay',cache),('ro',readonly)]
flags=[]
# Deliberately scrambled: backend must order by ancestry.
for mode,path in reversed(rules):flags+=['--folder-rule',f'{mode}\t{path}']
code='''from pathlib import Path
import sys
root=Path(sys.argv[1]);(root/'new-layer').write_text('private');(root/'original').unlink(missing_ok=True)
(root/'shared'/'new-real').write_text('host');(root/'shared'/'cache'/'new-cache').write_text('private')
try:(root/'read-only'/'bad').write_text('bad')
except PermissionError:pass
except OSError as e:
 assert e.errno==30,e
else:raise AssertionError('read-only folder is writable')
assert not (root/'original').exists()
print('nested writes and read-only checks passed',flush=True)
'''
for mode in ('layer','private'):
    for d in (project,shared,cache):
        for f in ('new-layer','new-real','new-cache'):(d/f).unlink(missing_ok=True)
    if mode=='layer':cmd=[a.unshare,'--user','--map-current-user','--keep-caps','--mount','--propagation','private','--',a.core,'profile-run',*flags,str(data),'offline','0','', '--',sys.executable,'-c',code,str(project)]
    else:cmd=[a.core,'fs-sandbox','--bwrap',a.bwrap,'--dbus-proxy','/nonexistent', 'synthetic','--name','test',*flags,'--',sys.executable,'-c',code,str(project)]
    r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    (root/f'{mode}.log').write_text(r.stdout+r.stderr)
    assert r.returncode==0,(mode,r.returncode,r.stdout,r.stderr)
    assert (project/'original').read_text()=='host'
    assert not (project/'new-layer').exists()
    assert (shared/'new-real').read_text()=='host'
    assert not (cache/'new-cache').exists()
    assert not (readonly/'bad').exists()
    print(f'PASS {mode}: overlay → real → overlay, sibling read-only; host contents preserved',flush=True)
