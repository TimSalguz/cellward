"""A pointer for headless sway, moved and clicked through a FIFO
(tests/vm-window.nix, the frame's buttons).

Headless sway has no input device, and a seat without a pointer device has
no pointer capability: programs make no wl_pointer, and the proxy's frame
hears nothing. sway's `seat … cursor set|press` would click, but moves the
cursor without a motion event, and a window being moved or resized follows
motion events only. So this client holds a virtual pointer
(zwlr_virtual_pointer_v1, which sway gives unrestricted clients) on the seat
for as long as it runs, and moves and clicks it as the lines written to the
FIFO say:

    move <x> <y>       to (x, y), logical pixels of the layout
    press | release [right]    the left button, or the right one

Usage: python3 vm-pointer.py <fifo> <layout width> <layout height>, with
WAYLAND_DISPLAY and XDG_RUNTIME_DIR. Raw Wayland on the socket: the VM has
Python and no Wayland library for it.
"""

import os
import select
import socket
import struct
import sys
import time

fifo, extent_w, extent_h = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
display = os.environ["WAYLAND_DISPLAY"]
path = display if display.startswith("/") else os.path.join(os.environ["XDG_RUNTIME_DIR"], display)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)


def send(obj, opcode, payload=b""):
    sock.sendall(struct.pack("=II", obj, ((8 + len(payload)) << 16) | opcode) + payload)


def string(text):
    data = text.encode() + b"\0"
    return struct.pack("=I", len(data)) + data + b"\0" * (-len(data) % 4)


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
            sys.exit("vm-pointer: the compositor is gone")
        received += chunk


# wl_display.get_registry → 2, then wl_display.sync → 3: every global is in
# when the sync is done.
send(1, 1, struct.pack("=I", 2))
send(1, 0, struct.pack("=I", 3))
names = {}
for obj, opcode, args in events():
    if obj == 2 and opcode == 0:
        name, length = struct.unpack_from("=II", args)
        names[args[8 : 8 + length - 1].decode()] = name
    elif obj == 3 and opcode == 0:
        break


def bind(interface, version, new_id):
    send(2, 0, struct.pack("=I", names[interface]) + string(interface) + struct.pack("=II", version, new_id))


bind("wl_seat", 1, 4)
bind("zwlr_virtual_pointer_manager_v1", 1, 5)
# create_virtual_pointer(seat 4, id 6)
send(5, 0, struct.pack("=II", 4, 6))

BTN_LEFT = 0x110
BTN_RIGHT = 0x111
start = time.monotonic()


def now():
    return int((time.monotonic() - start) * 1000) & 0xFFFFFFFF


def act(line):
    words = line.split()
    if not words:
        return
    if words[0] == "move":
        x, y = int(words[1]), int(words[2])
        # motion_absolute(time, x, y, x_extent, y_extent)
        send(6, 1, struct.pack("=IIIII", now(), x, y, extent_w, extent_h))
    elif words[0] in ("press", "release"):
        # button(time, button, state): the left one, or `right`
        button = BTN_RIGHT if words[1:] == ["right"] else BTN_LEFT
        send(6, 2, struct.pack("=III", now(), button, 1 if words[0] == "press" else 0))
    else:
        print(f"vm-pointer: what is {line!r}?", file=sys.stderr)
        return
    send(6, 4)  # frame


if not os.path.exists(fifo):
    os.mkfifo(fifo)
# Read and write: never an end of file between two writers.
commands = os.open(fifo, os.O_RDWR)
pending = b""
print("vm-pointer: ready", flush=True)
while True:
    ready, _, _ = select.select([sock, commands], [], [])
    if sock in ready and not sock.recv(4096):
        sys.exit("vm-pointer: the compositor is gone")
    if commands in ready:
        pending += os.read(commands, 4096)
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            act(line.decode())
