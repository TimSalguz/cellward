# Exec'd by tests/vm.nix in the test script's globals (the script's
# 128 KiB limit, 2026-09-28): the per-container trust section, moved out as
# it was. It uses the script's helpers (alice, in_container, machine).
# --- Per-container trust (docs/CERTIFICATES.md) ------------------------
# A CA generated here and nowhere else. On NixOS every bundle path is a
# symlink chain into ONE store file, and the layer binds over that file
# in the launch's own mount namespace — this is the one place that
# layout is exercised (the CI smoke runs on Ubuntu, a plain file).
CA = "/tmp/vmca"

# A layer container covers the whole home (docs/PERMISSIONS.md §11.3):
# what it writes stays in its layer — a dotfile, a new file anywhere —
# a granted path is written in the real home, a mount below the home
# is read-only unless granted, the project's state stays hidden and the
# other containers' storage is not seen.
with subtest("layer container: the whole home under its layer, grants in the real one"):
    alice("cellward profile create vmlayer")
    alice("mkdir -p ~/vmshare ~/.local/state/vpn-profiles/other/home && echo secret > ~/.local/state/vpn-profiles/other/home/data")
    alice("cellward container grant vmlayer ~/vmshare")
    in_container("vmlayer", "direct", "sh -c 'echo layer > $HOME/layer-only && echo real > $HOME/vmshare/f'")
    machine.fail("test -e /home/alice/layer-only")
    machine.succeed("grep -q real /home/alice/vmshare/f")
    machine.succeed("grep -q layer /home/alice/.local/state/vpn-profiles/vmlayer/home/upper/layer-only")
    # The container sees what it wrote, and not another container's data.
    in_container("vmlayer", "direct", "grep -q layer $HOME/layer-only")
    in_container("vmlayer", "direct", "sh -c '! cat $HOME/.local/state/vpn-profiles/other/home/data'")

# One name, one container, the kind of home a property of it
# (docs/PERMISSIONS.md §11.7): the main home is the real one under a
# container's name; a change of kind sets the old kind's data aside and
# brings them back; one launch is one container.
with subtest("one name: the main home, a change of kind, one container a launch"):
    alice("cellward container create vmmain --home main")
    in_container("vmmain", "direct", "sh -c 'echo m > $HOME/main-probe'")
    machine.succeed("grep -q m /home/alice/main-probe")
    alice("cellward container create vmkind")
    in_container("vmkind", "direct", "sh -c 'echo p > $HOME/kind-probe'")
    machine.succeed("grep -q p /home/alice/.local/state/vpn-profiles/vmkind/home/kind-probe")
    alice("cellward container set vmkind home layer")
    machine.succeed("grep -q p /home/alice/.local/state/vpn-profiles/vmkind/home.private/kind-probe")
    in_container("vmkind", "direct", "sh -c '! test -e $HOME/kind-probe && test -e $HOME/main-probe'")
    alice("cellward container set vmkind home private")
    in_container("vmkind", "direct", "grep -q p $HOME/kind-probe")
    # The old words name the same container; two at once is a refusal.
    alice("cellward run direct --sandbox vmkind -- sh -c 'grep -q p $HOME/kind-probe'")
    # A sandbox in the host's network reaches no abstract socket of the
    # outside — the host's X server listens there (review 2026-09-27;
    # Landlock scopes, Linux 6.12).
    release = machine.succeed("uname -r").strip()
    if tuple(int(x) for x in release.split("-")[0].split(".")[:2]) >= (6, 12):
        alice("systemd-run --user --unit=vmabstract socat ABSTRACT-LISTEN:vz-outside,fork OPEN:/dev/null")
        machine.wait_until_succeeds("grep -q '@vz-outside' /proc/net/unix")
        alice("socat -u OPEN:/dev/null ABSTRACT-CONNECT:vz-outside")
        alice(
            "sh -c '! cellward run direct --sandbox vmkind -- "
            "socat -u OPEN:/dev/null ABSTRACT-CONNECT:vz-outside'"
        )
        alice("systemctl --user stop vmabstract")
    else:
        print(f"kernel {release}: no Landlock scopes, the abstract socket check is skipped")
    alice("sh -c '! cellward run direct --profile vmlayer --sandbox vmkind -- true'")
    alice("sh -c '! cellward container create main'")
    out = alice("cellward container show vmmain")
    assert "основной дом" in out, out

with subtest("trust: a CA and a server certificate made on the fly"):
    alice(
        f"mkdir -p {CA} && cd {CA} && "
        "openssl req -x509 -newkey rsa:2048 -nodes -days 2 "
        "-subj '/CN=vpn-zones vm CA' "
        "-addext 'basicConstraints=critical,CA:TRUE' "
        "-addext 'keyUsage=critical,keyCertSign,cRLSign' "
        "-keyout ca.key -out ca.pem 2>/dev/null && "
        "openssl req -newkey rsa:2048 -nodes -subj '/CN=tls.internal' "
        "-keyout srv.key -out srv.csr 2>/dev/null && "
        "printf 'subjectAltName=DNS:tls.internal\\n' > ext && "
        "openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key "
        "-CAcreateserial -days 2 -extfile ext -out srv.pem 2>/dev/null"
    )
    alice("cellward profile create vmca && cellward profile create vmnoca")
    alice(f"cellward trust add vmca {CA}/ca.pem --yes")

with subtest("trust: the container trusts it, through the store-file bind and p11-kit"):
    in_container("vmca", "direct", f"openssl verify {CA}/srv.pem")
    in_container("vmca", "direct", f"openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt {CA}/srv.pem")
    # p11-kit is what NSS reads on NixOS (libnssckbi.so is p11-kit-trust).
    out = in_container("vmca", "direct", "trust list --filter=ca-anchors")
    assert "vpn-zones vm CA" in out, f"p11-kit does not see the container's CA:\n{out}"
    out = in_container("vmca", "direct", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb'")
    assert "vpn-zones " in out, f"the container's NSS database lacks the CA:\n{out}"
    # Through a zone too: the layer lives in the launch's namespace, not
    # the zone's. The database made anew in there — certutil's box
    # inside the zone's user namespace (review 2026-09-27).
    alice("rm -rf ~/.local/state/vpn-profiles/vmca/home/upper/.pki")
    in_container("vmca", "vmsmoke", f"openssl verify {CA}/srv.pem")
    out = in_container("vmca", "vmsmoke", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb'")
    assert "vpn-zones " in out, f"no CA in the database made in the zone:\n{out}"

# A sandboxed program sees its own home only, and the trust layer the
# real one: a link it leaves in its database must not lead the
# container's roots into the host's (review 2026-09-27).
with subtest("trust: a sandbox's links do not lead its roots into the host's database"):
    alice("mkdir -p ~/hostdb && certutil -N --empty-password -d sql:/home/alice/hostdb")
    alice("cellward container create vmcasb")
    alice(
        "mkdir -p ~/.local/state/vpn-profiles/vmcasb/home/.pki/nssdb && "
        "ln -s /home/alice/hostdb/cert9.db "
        "~/.local/state/vpn-profiles/vmcasb/home/.pki/nssdb/cert9.db"
    )
    alice(f"cellward trust add vmcasb {CA}/ca.pem --yes || true")
    alice("cellward run direct --container vmcasb -- true || true")
    out = alice("certutil -L -d sql:/home/alice/hostdb")
    assert "vpn-zones " not in out, f"the host's database got the container's CA:\n{out}"
    # Put right, the sandbox has it in its own.
    alice("rm ~/.local/state/vpn-profiles/vmcasb/home/.pki/nssdb/cert9.db")
    alice("cellward run direct --container vmcasb -- true")
    out = in_container("vmcasb", "direct", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb'")
    assert "vpn-zones " in out, f"the sandbox's own database lacks the CA:\n{out}"
    alice("rm -rf ~/hostdb")

with subtest("trust: the host and the container next door do not"):
    machine.fail(f"su -l alice -c 'openssl verify {CA}/srv.pem'")
    machine.fail("su -l alice -c 'trust list --filter=ca-anchors | grep -q \"vpn-zones vm CA\"'")
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        f"cellward run direct --profile vmnoca -- openssl verify {CA}/srv.pem'"
    )
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        f"cellward run vmsmoke --profile vmnoca -- openssl verify {CA}/srv.pem'"
    )
    machine.fail("grep -q 'vpn-zones vm CA' /etc/ssl/certs/ca-certificates.crt")
    machine.fail(
        "test -f /home/alice/.pki/nssdb/cert9.db && "
        "su -l alice -c 'certutil -L -d sql:/home/alice/.pki/nssdb' | grep -q 'vpn-zones '"
    )

# The decision that makes environment leaks harmless: inside the
# container the variables name the SYSTEM path. A program that pushes
# them into the user manager changes nothing for anybody else — proven
# with the push actually having happened.
with subtest("trust: a leaked environment gives the host nothing"):
    in_container(
        "vmca",
        "direct",
        "systemctl --user import-environment SSL_CERT_FILE NIX_SSL_CERT_FILE",
    )
    out = alice("systemctl --user show-environment")
    assert "NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" in out, out
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        f"systemd-run --user --wait --pipe --quiet openssl verify {CA}/srv.pem'"
    )
    alice("systemctl --user unset-environment SSL_CERT_FILE NIX_SSL_CERT_FILE")

with subtest("trust: after a reset the container does not trust it either"):
    alice("cellward trust reset vmca")
    machine.fail(
        "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
        f"cellward run direct --profile vmca -- openssl verify {CA}/srv.pem'"
    )
    out = in_container("vmca", "direct", "sh -c 'certutil -L -d sql:$HOME/.pki/nssdb || true'")
    assert "vpn-zones " not in out, f"the reset left the CA in the NSS database:\n{out}"
    alice("cellward down vmsmoke")
