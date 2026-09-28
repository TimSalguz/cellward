# A tray icon as a program in a zone has it (tests/vm-promise-tray.py): on
# the session bus it owns the name argv[1] and answers a tray host's
# Properties.GetAll with a 16x16 picture, transparent, and a tooltip — what
# Electron and Qt answer, spoken on the socket itself (no D-Bus library in
# the VM's Python).
import os, socket, struct, sys

NAME = sys.argv[1]


def pad(b, n):
    return b + b"\0" * ((-len(b)) % n)


class W:
    """Little-endian marshalling; alignment relative to the body, which a
    message starts 8-aligned."""

    def __init__(self):
        self.b = b""

    def align(self, n):
        self.b = pad(self.b, n)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack("<I", v)

    def s(self, v):
        e = v.encode()
        self.u32(len(e))
        self.b += e + b"\0"

    def g(self, v):
        self.b += bytes([len(v)]) + v.encode() + b"\0"

    def pictures(self, pics):
        self.u32(0)
        at = len(self.b) - 4
        self.align(8)
        start = len(self.b)
        for w, h, px in pics:
            self.align(8)
            self.u32(w)
            self.u32(h)
            self.u32(len(px))
            self.b += px
        self.b = self.b[:at] + struct.pack("<I", len(self.b) - start) + self.b[at + 4 :]


def message(kind, serial, fields, body=b""):
    f = W()
    for code, sig, val in fields:
        f.align(8)
        f.b += bytes([code])
        f.g(sig)
        if sig == "u":
            f.u32(val)
        elif sig == "g":
            f.g(val)
        else:
            f.s(val)
    # The fields' offsets are 16 more than W counted: 16 is 8-aligned.
    head = b"l" + bytes([kind, 0, 1]) + struct.pack("<III", len(body), serial, len(f.b))
    return pad(head + f.b, 8) + body


def call(serial, member, sig="", body=b""):
    fields = [
        (1, "o", "/org/freedesktop/DBus"),
        (2, "s", "org.freedesktop.DBus"),
        (3, "s", member),
        (6, "s", "org.freedesktop.DBus"),
    ]
    if sig:
        fields.append((8, "g", sig))
    return message(1, serial, fields, body)


def fields_of(msg):
    """serial and the header fields of a whole message."""
    serial = struct.unpack_from("<I", msg, 8)[0]
    end = 16 + struct.unpack_from("<I", msg, 12)[0]
    pos, out = 16, {}
    while pos < end:
        pos += (-pos) % 8
        if pos >= end:
            break
        code = msg[pos]
        n = msg[pos + 1]
        sig = msg[pos + 2 : pos + 2 + n].decode()
        pos += 3 + n
        if sig in ("s", "o"):
            pos += (-pos) % 4
            ln = struct.unpack_from("<I", msg, pos)[0]
            out[code] = msg[pos + 4 : pos + 4 + ln].decode()
            pos += 5 + ln
        elif sig == "g":
            ln = msg[pos]
            out[code] = msg[pos + 1 : pos + 1 + ln].decode()
            pos += 2 + ln
        elif sig == "u":
            pos += (-pos) % 4
            out[code] = struct.unpack_from("<I", msg, pos)[0]
            pos += 4
        else:
            raise SystemExit(f"header field of type {sig}")
    return serial, out


def all_properties():
    w = W()
    w.u32(0)
    at = len(w.b) - 4
    w.align(8)
    start = len(w.b)
    for key, value in [("Category", "ApplicationStatus"), ("Id", "vmtray")]:
        w.align(8)
        w.s(key)
        w.g("s")
        w.s(value)
    w.align(8)
    w.s("IconPixmap")
    w.g("a(iiay)")
    w.pictures([(16, 16, bytes(16 * 16 * 4))])
    w.align(8)
    w.s("ToolTip")
    w.g("(sa(iiay)ss)")
    w.align(8)
    w.s("")
    w.pictures([])
    w.s("Item")
    w.s("own text")
    w.b = w.b[:at] + struct.pack("<I", len(w.b) - start) + w.b[at + 4 :]
    return w.b


c = socket.socket(socket.AF_UNIX)
c.connect("/run/user/1000/bus")
c.sendall(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n")
assert c.recv(4096).startswith(b"OK")
name = W()
name.s(NAME)
name.u32(4)
c.sendall(b"BEGIN\r\n" + call(1, "Hello") + call(2, "RequestName", "su", name.b))
buf, serial = b"", 10
while True:
    d = c.recv(65536)
    if not d:
        break
    buf += d
    while len(buf) >= 16:
        body = struct.unpack_from("<I", buf, 4)[0]
        fl = struct.unpack_from("<I", buf, 12)[0]
        total = 16 + fl + ((-(16 + fl)) % 8) + body
        if len(buf) < total:
            break
        msg, buf = buf[:total], buf[total:]
        their, f = fields_of(msg)
        if msg[1] == 1 and f.get(3) == "GetAll" and 7 in f:
            serial += 1
            c.sendall(
                message(
                    2,
                    serial,
                    [(5, "u", their), (6, "s", f[7]), (8, "g", "a{sv}")],
                    all_properties(),
                )
            )
