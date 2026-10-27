"""Default-launch filesystem checks loaded by vm-window.nix foldersOnly."""

def stop_folder_container(name):
    # Stop the holder's unit directly: the last process may already have
    # stopped it, which the interactive CLI deliberately reports as code 2.
    unit = "vpn-zone-container@" + name.replace("-", r"\x2d") + ".service"
    alice("systemctl --user stop " + shlex.quote(unit))

with subtest("private and whole-home layers share one mounted view across concurrent launches"):
    base = "/home/alice/Projects/cellward-folder-fixture"
    alice(f"mkdir -p {base}/shared/cache {base}/reference && printf host > {base}/original")
    probe = r'''
import errno,sys,time
from pathlib import Path
p=Path(sys.argv[1]); own=sys.argv[2]; other='two' if own=='one' else 'one'
# Cache a negative lookup before the other process creates its file.
(p/other).exists()
(p/own).write_text('layer')
(p/'shared'/own).write_text('real')
(p/'shared'/'cache'/own).write_text('private-cache')
try:(p/'reference'/'bad').write_text('bad')
except OSError as e: assert e.errno in (errno.EROFS,errno.EACCES),e
else:raise AssertionError('read-only folder was writable')
(Path.home()/('root-'+own)).write_text('container home')
deadline=time.monotonic()+30
while not (p/other).exists() or not (Path.home()/('root-'+other)).exists():
 assert time.monotonic()<deadline,'concurrent views did not see each other'
 time.sleep(.1)
assert (p/'shared'/'cache'/other).read_text()=='private-cache'
(p/'shared'/('coherent-'+own)).write_text('ok')
print('COHERENT '+own,flush=True)
time.sleep(1)
'''
    for kind in ("private", "layer"):
        c = "vmfolders-" + kind
        alice(f"cellward container create {c} --home {kind}")
        for mode, path in (("overlay", base), ("rw", base+"/shared"), ("overlay", base+"/shared/cache"), ("ro", base+"/reference")):
            alice(f"cellward container folder {c} {mode} {path}")
        alice(f"rm -f {base}/shared/one {base}/shared/two {base}/shared/coherent-one {base}/shared/coherent-two")
        for name in ("one", "two"):
            command = f"cellward run offline --container {c} -- python3 -c {shlex.quote(probe)} {base} {name}"
            alice(f"systemd-run --user --unit=folders-{kind}-{name} " + command)
            machine.wait_until_succeeds(f"test -e {base}/shared/{name}", timeout=60)
        for name in ("one", "two"):
            try:
                # Programs join the container's cgroup; their journal unit may
                # differ from the launch unit. Assert completion directly.
                machine.wait_until_succeeds(f"test -e {base}/shared/coherent-{name}", timeout=45)
            except Exception:
                print(alice("journalctl --user --no-pager -o cat -n 100"), flush=True)
                raise
        machine.succeed(f"test $(cat {base}/original) = host")
        for name in ("one", "two"):
            machine.fail(f"test -e {base}/{name}")
            machine.fail(f"test -e {base}/shared/cache/{name}")
            machine.fail(f"test -e /home/alice/root-{name}")
        machine.fail(f"test -e {base}/reference/bad")
        stop_folder_container(c)
        # New instance, same persistent private changes.
        alice(f"cellward run offline --container {c} -- test -f {base}/one")
        alice(f"cellward run offline --container {c} -- test -f {base}/shared/cache/two")
        stop_folder_container(c)
print("PASS: default private/layer containers, concurrent shared overlays, nested overrides, host isolation, restart persistence")
