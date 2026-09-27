"""A program that asks for the focus back every time it loses it, from the
one click it had (tests/vm-window.nix, the focus policy; rust/src/wl_focus.rs).

It opens a window with the app id it is given and waits for a click on it.
From then on, whenever its window loses the focus (the `activated` state
goes from its configure), it asks for it back as Qt's requestActivate()
does: a new xdg-activation token — the serial of the last input event it
had, the seat, its app id, its surface — and `activate` with it. Then a
sync: once that is done the compositor has had the request, whatever it
made of it. What it does goes to stdout, a line each:

    <app id>: click <serial>
    <app id>: asked <n>
    <app id>: synced <n>

Usage: python3 vm-activate.py <app id>, with WAYLAND_DISPLAY and
XDG_RUNTIME_DIR. Raw Wayland on the socket, as tests/vm-pointer.py: the VM
has Python and no Wayland library for it.
"""

import os
import socket
import struct
import sys

app_id = sys.argv[1]
display = os.environ["WAYLAND_DISPLAY"]
path = display if display.startswith("/") else os.path.join(os.environ["XDG_RUNTIME_DIR"], display)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)


def say(what):
    print(f"{app_id}: {what}", flush=True)


def send(obj, opcode, payload=b"", fd=None):
    data = struct.pack("=II", obj, ((8 + len(payload)) << 16) | opcode) + payload
    if fd is None:
        sock.sendall(data)
    else:
        sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("=i", fd))])


def uint(*values):
    return struct.pack(f"={len(values)}I", *values)


def string(text):
    data = text.encode() + b"\0"
    return struct.pack("=I", len(data)) + data + b"\0" * (-len(data) % 4)


def read_string(args, at=0):
    length = struct.unpack_from("=I", args, at)[0]
    return args[at + 4 : at + 4 + length - 1].decode()


received = b""


def events():
    """Events from the compositor, (object, opcode, arguments), as they come."""
    global received
    while True:
        while len(received) >= 8:
            obj, word = struct.unpack_from("=II", received)
            size = word >> 16
            if len(received) < size:
                break
            message, received = received[:size], received[size:]
            yield obj, word & 0xFFFF, message[8:]
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit(f"{app_id}: the compositor is gone")
        received += chunk


# wl_display.get_registry → 2, then wl_display.sync → 3: every global is in
# when the sync is done.
send(1, 1, uint(2))
send(1, 0, uint(3))
names = {}
for obj, opcode, args in events():
    if obj == 2 and opcode == 0:
        names[read_string(args, 4)] = struct.unpack_from("=I", args)[0]
    elif obj == 3 and opcode == 0:
        break

COMPOSITOR, SHM, WM_BASE, SEAT, ACTIVATION = 4, 5, 6, 7, 8
SURFACE, XDG_SURFACE, TOPLEVEL, POINTER = 9, 10, 11, 12
last_id = 20


def new_id():
    global last_id
    last_id += 1
    return last_id


def bind(interface, version, new):
    send(2, 0, uint(names[interface]) + string(interface) + uint(version, new))


bind("wl_compositor", 4, COMPOSITOR)
bind("wl_shm", 1, SHM)
bind("xdg_wm_base", 1, WM_BASE)
bind("wl_seat", 5, SEAT)
bind("xdg_activation_v1", 1, ACTIVATION)
send(COMPOSITOR, 0, uint(SURFACE))
send(WM_BASE, 2, uint(XDG_SURFACE, SURFACE))
send(XDG_SURFACE, 1, uint(TOPLEVEL))
send(TOPLEVEL, 3, string(app_id))  # set_app_id
send(TOPLEVEL, 2, string(app_id))  # set_title
send(SURFACE, 6)  # commit: the first configure comes


def buffer(width, height):
    """A wl_buffer of one colour, width × height, XRGB8888."""
    size = width * height * 4
    fd = os.memfd_create("vm-activate")
    os.ftruncate(fd, size)
    os.write(fd, b"\x40\x80\x20\xff" * (width * height))
    pool = new_id()
    send(SHM, 0, uint(pool) + struct.pack("=i", size), fd=fd)
    os.close(fd)
    made = new_id()
    send(pool, 0, uint(made) + struct.pack("=iiiiI", 0, width, height, width * 4, 1))
    send(pool, 1)  # destroy: the buffer keeps the memory
    return made


size = (300, 300)
drawn = None
activated = False
pending = False
serial = None
asked = 0
tokens = {}
syncs = {}
pointer = False


def ask():
    """A token from the last input event's serial, as Qt makes one."""
    global asked
    asked += 1
    token = new_id()
    tokens[token] = asked
    send(ACTIVATION, 1, uint(token))  # get_activation_token
    send(token, 0, uint(serial, SEAT))  # set_serial
    send(token, 1, string(app_id))  # set_app_id
    send(token, 2, uint(SURFACE))  # set_surface
    send(token, 3)  # commit


for obj, opcode, args in events():
    if obj == 1 and opcode == 0:
        sys.exit(f"{app_id}: protocol error {read_string(args, 8)}")
    elif obj == WM_BASE and opcode == 0:  # ping
        send(WM_BASE, 3, args[:4])
    elif obj == TOPLEVEL and opcode == 0:  # configure(width, height, states)
        width, height, length = struct.unpack_from("=iiI", args)
        if width > 0 and height > 0:
            size = (width, height)
        pending = 4 in struct.unpack_from(f"={length // 4}I", args, 12)
    elif obj == XDG_SURFACE and opcode == 0:  # configure(serial)
        send(XDG_SURFACE, 4, args[:4])  # ack_configure
        if drawn != size:
            send(SURFACE, 1, uint(buffer(*size), 0, 0))  # attach
            send(SURFACE, 2, struct.pack("=iiii", 0, 0, *size))  # damage
            drawn = size
        send(SURFACE, 6)  # commit
        lost = activated and not pending
        activated = pending
        if lost and serial is not None:
            ask()
    elif obj == SEAT and opcode == 0:  # capabilities
        if struct.unpack_from("=I", args)[0] & 1 and not pointer:
            pointer = True
            send(SEAT, 0, uint(POINTER))  # get_pointer
    elif obj == POINTER and opcode == 3:  # button(serial, time, button, state)
        serial = struct.unpack_from("=I", args)[0]
        say(f"click {serial}")
    elif obj in tokens and opcode == 0:  # done(token)
        n = tokens.pop(obj)
        send(ACTIVATION, 2, string(read_string(args)) + uint(SURFACE))  # activate
        send(obj, 4)  # destroy
        say(f"asked {n}")
        callback = new_id()
        syncs[callback] = n
        send(1, 0, uint(callback))
    elif obj in syncs and opcode == 0:
        say(f"synced {syncs.pop(obj)}")
