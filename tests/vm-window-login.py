"""tests/vm-window.nix, continued: a network whose login is asked
(docs/PERMISSIONS.md §11.16, step 2): a real ocserv on the machine that asks
a password and then a one-time code (TOTP); an OpenConnect zone without a
`PasswordFile`, so its login is asked; a launch into it brings the connect
window's form. A wrong
password: the form again, with what went wrong. The right one and the code:
the zone comes up with them, the program runs — and the password is on no
disk and on no command line.

Executed by the main test script with exec(), in its globals: machine,
alice, display, swaysock, find.
"""

import re

SRV = "192.0.2.10"
PASSWORD = "login-secret"
# The TOTP secret (hex), as ocserv's users file and oathtool take it.
OTP_SECRET = "3132333435363738393031323334353637383930"
OCDIR = "/tmp/vm-ocserv"


def listed(app_id):
    return (
        f"su -l alice -c 'SWAYSOCK={swaysock} swaymsg -t get_tree' "
        f"| grep -q '\"app_id\": *\"{app_id}\"'"
    )


def the_form(name):
    """The login form up (the window with `login`), shown."""
    machine.wait_until_succeeds("pgrep -f '[v]pn-zone-window login'", timeout=60)
    machine.sleep(2)
    alice(f"WAYLAND_DISPLAY={display} grim /tmp/{name}.png")
    machine.copy_from_vm(f"/tmp/{name}.png", "")


def type_into_the_form(password, code):
    """The password, Tab, the code, Enter: one wtype, its first key after
    the form's guard (the focus is on the password field then)."""
    words = f"-s 3500 {password} -k Tab"
    if code:
        words += f" {code}"
    alice(f"WAYLAND_DISPLAY={display} wtype {words} -s 300 -k Return")
    machine.wait_until_fails("pgrep -f '[v]pn-zone-window login'", timeout=30)


with subtest("a network that asks its login: the form, then the zone with it"):
    # The gateway: ocserv on an address of its own on lo — as the smoke
    # test's, and for its reason: pasta copies the host's addresses, and
    # this one is none of them — asking the password, then a TOTP.
    machine.succeed(f"ip addr add {SRV}/32 dev lo")
    machine.succeed(f"mkdir -p {OCDIR} && chmod 755 {OCDIR}")
    machine.succeed(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=vpn-login.invalid "
        f"-addext subjectAltName=IP:{SRV} -keyout {OCDIR}/key.pem -out {OCDIR}/cert.pem"
    )
    hashed = machine.succeed(f"openssl passwd -6 {PASSWORD}").strip()
    machine.succeed(f"printf 'ivan:*:%s\\n' '{hashed}' > {OCDIR}/passwd")
    machine.succeed(f"printf 'HOTP/T30 ivan - {OTP_SECRET}\\n' > {OCDIR}/otp")
    conf = "\n".join(
        [
            f'auth = "plain[passwd={OCDIR}/passwd,otp={OCDIR}/otp]"',
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
    type_into_the_form("wrong-one", "")
    the_form("connect-login-again")
    # The right one, and the code of now.
    code = machine.succeed(f"oathtool --totp {OTP_SECRET}").strip()
    type_into_the_form(PASSWORD, code)
    machine.wait_until_succeeds(listed("ocfoot"), timeout=120)
    status = json.loads(alice("cellward status --json"))
    work = next(n for n in status["networks"] if n["name"] == "ocwork")
    assert work["up"] and work["connection"] == {"value": "ask", "source": "default"}, work

    # Remembered: the user; the password nowhere on a disk, the socket gone.
    last = alice("cat ~/.local/state/vpn-zones/ocwork/login")
    assert "user\tivan" in last, last
    machine.fail(
        f"grep -rsl -- {PASSWORD} /home/alice/.local /home/alice/.config /tmp/ocwork.conf"
    )
    machine.fail("test -e /run/user/1000/vpn-zones/login/ocwork.sock")

    alice("systemctl --user stop vmoclogin || true")
    machine.wait_until_fails(listed("ocfoot"), timeout=30)
    alice("cellward down ocwork")
    machine.succeed("systemctl stop vmocserv")
