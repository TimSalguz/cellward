"""tests/vm-window.nix, continued: a network whose login is asked
(docs/PERMISSIONS.md §11.16, step 2): a real ocserv on the machine that asks
a password; an OpenConnect zone without a
`PasswordFile`, so its login is asked; a launch into it brings the connect
window's form. A wrong password: the form again, with what went wrong. The
right one: the zone comes up, the program runs, the
person is told it is connected — and the password is on no disk and on no
command line.

TODO: cover an OTP challenge in a separate VM scenario. This one isolates
password rejection and retry so a failure at another gateway stage cannot
hide that regression.

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find.
"""

import re

SRV = "192.0.2.10"
PASSWORD = "login-secret"
OCDIR = "/tmp/vm-ocserv"


def window_focus():
    tree = json.loads(alice(f"SWAYSOCK={swaysock} swaymsg -t get_tree -r"))
    windows = []

    def walk(node):
        if node.get("app_id") or node.get("focused"):
            windows.append(
                (node.get("app_id"), node.get("name"), node.get("focused"), node.get("pid"))
            )
        for child in node.get("nodes", []) + node.get("floating_nodes", []):
            walk(child)

    walk(tree)
    return windows


def listed(app_id):
    return (
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' "
        f"| grep -q '\"app_id\": *\"{app_id}\"'"
    )


def the_form(name):
    """The login form up (the window with `login`), shown."""
    machine.wait_until_succeeds("pgrep -f '[v]pn-zone-window login'", timeout=60)
    machine.sleep(2)
    print(f"VPN login focus before input: {window_focus()}")
    alice(f"WAYLAND_DISPLAY={display} grim /tmp/{name}.png")
    machine.copy_from_vm(f"/tmp/{name}.png", "")


def type_into_the_form(password):
    """The password, Tab, Enter: one wtype, its first key after
    the form's guard (the focus is on the password field then)."""
    words = f"-s 3500 {password} -k Tab"
    login_pid = machine.succeed("pgrep -f '[v]pn-zone-window login'").strip()
    alice(f"WAYLAND_DISPLAY={display} wtype {words} -s 300 -k Return")
    try:
        # On a rejected password the next form can appear before the next
        # poll, so watch the old window, not whether *any* form exists.
        machine.wait_until_fails(f"kill -0 {login_pid}", timeout=30)
    except Exception:
        print(f"VPN login focus after timed-out input: {window_focus()}")
        alice(f"WAYLAND_DISPLAY={display} grim /tmp/connect-login-stuck.png")
        machine.copy_from_vm("/tmp/connect-login-stuck.png", "")
        raise


with subtest("a network that asks its login: the form, then the zone with it"):
    # The gateway: ocserv on an address of its own on lo — as the smoke
    # test's, and for its reason: pasta copies the host's addresses, and
    # this one is none of them — asking the password.
    machine.succeed(f"ip addr add {SRV}/32 dev lo")
    machine.succeed(f"mkdir -p {OCDIR} && chmod 755 {OCDIR}")
    machine.succeed(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=vpn-login.invalid "
        f"-addext subjectAltName=IP:{SRV} -keyout {OCDIR}/key.pem -out {OCDIR}/cert.pem"
    )
    hashed = machine.succeed(f"openssl passwd -6 {PASSWORD}").strip()
    machine.succeed(f"printf 'ivan:*:%s\\n' '{hashed}' > {OCDIR}/passwd")
    conf = "\n".join(
        [
            f'auth = "plain[passwd={OCDIR}/passwd]"',
            "tcp-port = 4443",
            "udp-port = 4443",
            "run-as-user = nobody",
            "run-as-group = nogroup",
            f"socket-file = {OCDIR}/socket",
            f"server-cert = {OCDIR}/cert.pem",
            f"server-key = {OCDIR}/key.pem",
            "isolate-workers = false",
            "max-clients = 4",
            "max-same-clients = 2",
            "try-mtu-discovery = false",
            "device = ocvmtun",
            "predictable-ips = true",
            "ipv4-network = 192.168.223.0",
            "ipv4-netmask = 255.255.255.0",
            "dns = 192.168.223.1",
            "ping-leases = false",
            "cisco-client-compat = true",
            "dtls-legacy = true",
            "auth-timeout = 40",
            'tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"',
            f"pid-file = {OCDIR}/ocserv.pid",
        ]
    )
    machine.succeed(f"cat > {OCDIR}/ocserv.conf <<'EOF'\n{conf}\nEOF")
    machine.succeed(f"chmod -R a+rX {OCDIR}")
    machine.succeed(f"systemd-run --unit=vmocserv ocserv -c {OCDIR}/ocserv.conf -f -d 3")
    machine.wait_until_succeeds(f"bash -c 'exec 3<>/dev/tcp/{SRV}/4443'", timeout=30)
    # Its pin, as the client says it (and it refuses: self-signed).
    probe = alice(
        f"openconnect --non-inter --protocol=anyconnect {SRV}:4443 </dev/null 2>&1 || true"
    )
    found = re.search(r"pin-sha256:[A-Za-z0-9+/=]+", probe)
    assert found, probe
    pin = found.group(0)
    alice(
        "printf '%s\\n' '[OpenConnect]' 'Server = "
        + SRV
        + ":4443' 'Protocol = anyconnect' 'User = ivan' 'ServerCert = "
        + pin
        + "' 'Args = --no-dtls' > /tmp/ocwork.conf"
    )
    alice("cellward add ocwork /tmp/ocwork.conf")
    # A network whose login is asked asks by default.
    out = alice("cellward connection ocwork")
    assert "спросить (ask) (умолчание)" in out, out

    alice(
        f"systemd-run --user --unit=vmoclogin --setenv=WAYLAND_DISPLAY={display} "
        "cellward run ocwork -- foot --app-id ocfoot"
    )
    # A wrong password: the gateway refuses, and the form comes again.
    the_form("connect-login")
    type_into_the_form("wrong-one")
    the_form("connect-login-again")
    type_into_the_form(PASSWORD)
    try:
        machine.wait_until_succeeds(listed("ocfoot"), timeout=120)
    except Exception:
        print("ocserv authentication trace:")
        print(machine.succeed("journalctl -u vmocserv --no-pager -o cat | grep -Ei 'auth|fail|error|ivan' | tail -70"))
        print("cellward login trace:")
        print(alice("journalctl --user -u vmoclogin --no-pager -o cat | tail -50"))
        print("zone service trace:")
        print(alice("journalctl --user -u vpn-zone@ocwork --no-pager -o cat | tail -50"))
        print("login unit state:")
        print(alice("systemctl --user show vmoclogin -p ActiveState -p SubState -p ExecMainStatus"))
        raise
    # The person is told it is connected (step 3), once: the refused try
    # was no connection. A unit of its own — no daemon here, so its start is
    # what is looked for.
    connected = (
        "journalctl --no-pager | grep -F 'cellward: Сеть ocwork подключена' "
        "| grep -cF Started"
    )
    machine.wait_until_succeeds(connected, timeout=30)
    assert machine.succeed(connected).strip() == "1", machine.succeed(connected)
    status = json.loads(alice("cellward status --json"))
    work = next(n for n in status["networks"] if n["name"] == "ocwork")
    assert work["up"] and work["connection"] == {"value": "ask", "source": "default"}, work

    # The username comes from the config. Nothing was explicitly ticked to
    # remember, so the login file must not hold any secret.
    last = alice("cat ~/.local/state/vpn-zones/ocwork/login")
    assert PASSWORD not in last, last
    machine.fail(
        f"grep -rsl -- {PASSWORD} /home/alice/.local /home/alice/.config /tmp/ocwork.conf"
    )
    machine.fail("test -e /run/user/1000/vpn-zones/login/ocwork.sock")

    alice("systemctl --user stop vmoclogin || true")
    machine.wait_until_fails(listed("ocfoot"), timeout=30)
    alice("cellward down ocwork")
    machine.succeed("systemctl stop vmocserv")
