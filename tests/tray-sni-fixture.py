#!/usr/bin/env python3
"""Small real D-Bus tray item/watcher for compositor integration tests."""
import argparse
import array
import os
from pathlib import Path
import socket
import struct
import subprocess


def pad(data, alignment):
    data.extend(b"\0" * ((-len(data)) % alignment))


def string(value):
    data = value.encode()
    return struct.pack("<I", len(data)) + data + b"\0"


def strings(values):
    data = bytearray()
    for value in values:
        pad(data, 4)
        data.extend(string(value))
    return struct.pack("<I", len(data)) + data


def message(kind, serial, fields, body=b""):
    header = bytearray()
    for code, signature, value in fields:
        pad(header, 8)
        header.extend(bytes([code, 1, ord(signature), 0]))
        if signature in ("s", "o"):
            pad(header, 4)
            header.extend(string(value))
        elif signature == "u":
            pad(header, 4)
            header.extend(struct.pack("<I", value))
        elif signature == "g":
            data = value.encode()
            header.extend(bytes([len(data)]) + data + b"\0")
        else:
            raise AssertionError(signature)
    packet = bytearray(b"l" + bytes([kind, 0, 1]) + struct.pack("<III", len(body), serial, len(header)))
    packet.extend(header)
    pad(packet, 8)
    return packet + body


def read_string(data, pos):
    pos += (-pos) % 4
    length, = struct.unpack_from("<I", data, pos)
    assert data[pos + 4 + length] == 0
    return data[pos + 4:pos + 4 + length].decode(), pos + 5 + length


def parse(data):
    assert data[0] == ord("l")
    size, serial, length = struct.unpack_from("<III", data, 4)
    fields, pos = {}, 16
    while pos < 16 + length:
        pos += (-pos) % 8
        code, one, signature, zero = data[pos:pos + 4]
        assert one == 1 and zero == 0
        pos += 4
        if signature in (ord("s"), ord("o")):
            value, pos = read_string(data, pos)
        elif signature == ord("u"):
            pos += (-pos) % 4
            value, = struct.unpack_from("<I", data, pos)
            pos += 4
        elif signature == ord("g"):
            count = data[pos]
            value = data[pos + 1:pos + 1 + count].decode()
            pos += count + 2
        else:
            raise AssertionError(signature)
        fields[code] = value
    body = 16 + length
    body += (-body) % 8
    assert len(data) == body + size
    return data[1], serial, fields, data[body:]


class Bus:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.connect(str(path))
        uid = str(os.getuid()).encode().hex()
        self.socket.sendall(f"\0AUTH EXTERNAL {uid}\r\n".encode())
        assert self.line().startswith(b"OK ")
        self.socket.sendall(b"NEGOTIATE_UNIX_FD\r\n")
        assert self.line() == b"AGREE_UNIX_FD\r\n"
        self.socket.sendall(b"BEGIN\r\n")
        self.pending, self.serial = bytearray(), 0
        self.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello")

    def line(self):
        data = bytearray()
        while not data.endswith(b"\r\n"):
            byte = self.socket.recv(1)
            assert byte
            data.extend(byte)
        return data

    def receive(self):
        while True:
            if len(self.pending) >= 16:
                size, _, header = struct.unpack_from("<III", self.pending, 4)
                end = 16 + header
                end += (-end) % 8
                end += size
                assert end <= 1024 * 1024
                if len(self.pending) >= end:
                    data = bytes(self.pending[:end])
                    del self.pending[:end]
                    return parse(data)
            data, control, flags, _ = self.socket.recvmsg(65536, socket.CMSG_SPACE(64 * 4))
            assert data and not flags & socket.MSG_CTRUNC
            received = []
            for level, kind, contents in control:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array("i")
                    fds.frombytes(contents[:len(contents) // 4 * 4])
                    received.extend(fds)
            for fd in received:
                os.close(fd)
            assert not received, "process reference escaped the filter into the application"
            self.pending.extend(data)

    def call(self, service, path, interface, member, signature="", body=b""):
        self.serial += 1
        serial = self.serial
        fields = [(1, "o", path), (2, "s", interface), (3, "s", member), (6, "s", service)]
        if signature:
            fields.append((8, "g", signature))
        self.socket.sendall(message(1, serial, fields, body))
        while True:
            response = self.receive()
            if response[2].get(5) == serial:
                return response

    def reply(self, request, signature="", body=b"", error=None):
        self.serial += 1
        fields = [(5, "u", request[1]), (6, "s", request[2][7])]
        if error:
            fields.append((4, "s", error))
        if signature:
            fields.append((8, "g", signature))
        self.socket.sendall(message(3 if error else 2, self.serial, fields, body))

    def own(self, name):
        args = bytearray(string(name))
        pad(args, 4)
        args.extend(struct.pack("<I", 4))
        answer = self.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                           "RequestName", "su", args)
        assert answer[0] == 2 and struct.unpack_from("<I", answer[3])[0] in (1, 4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--watcher", action="store_true")
    parser.add_argument("--label", default="a")
    parser.add_argument("--object", default="/StatusNotifierItem")
    parser.add_argument("--foot", default="foot")
    args = parser.parse_args()
    root = Path(args.root)
    bus = Bus(args.socket)
    items = []
    if args.watcher:
        bus.own("org.kde.StatusNotifierWatcher")
        (root / "ready-watcher").write_text("ready")
    else:
        name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
        bus.own(name)
        registration = args.object if args.object != "/StatusNotifierItem" else name
        bus.call("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
                 "RegisterStatusNotifierItem", "s", string(registration))
        (root / ("ready-" + args.label)).write_text(str(os.getpid()))
    count, window = 0, None
    while True:
        request = bus.receive()
        if request[0] != 1:
            continue
        fields, body = request[2], request[3]
        if args.watcher and fields.get(3) == "RegisterStatusNotifierItem":
            value, _ = read_string(body, 0)
            entry = fields[7] + value if value.startswith("/") else value
            if entry not in items:
                items.append(entry)
            bus.reply(request)
        elif args.watcher and fields.get(3) == "Get":
            interface, pos = read_string(body, 0)
            prop, _ = read_string(body, pos)
            assert interface == "org.kde.StatusNotifierWatcher" and prop == "RegisteredStatusNotifierItems"
            bus.reply(request, "v", b"\x02as\0" + strings(items))
        elif not args.watcher and fields.get(3) == "Activate" and fields.get(1) == args.object:
            assert fields.get(2) in ("org.kde.StatusNotifierItem", "org.freedesktop.StatusNotifierItem")
            assert fields.get(8) == "ii" and body == b"\0" * 8 and fields.get(9, 0) == 0
            count += 1
            (root / ("activated-" + args.label)).write_text(str(count))
            if window is None or window.poll() is not None:
                window = subprocess.Popen([args.foot, "--app-id", "tray-source-" + args.label, "sleep", "120"])
                (root / ("window-pid-" + args.label)).write_text(str(window.pid))
            bus.reply(request)
        else:
            bus.reply(request, "s", string("unsupported fixture method"), "org.freedesktop.DBus.Error.UnknownMethod")


if __name__ == "__main__":
    main()
