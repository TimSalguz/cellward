"""A V4L2 program as Chromium and Firefox are one (tests/vm-camera.nix):
open the camera, ask what it is and for a format, map its buffers, stream
and take frames — each black — then stop. `block`: DQBUF waits for a frame;
`poll`: the file non-blocking, poll(2) first, as Firefox and Telegram do.

    python3 vm-camera-client.py <device> block|poll
"""

import fcntl
import mmap
import os
import select
import struct
import sys
import time


def ioc(direction, nr, size):
    return (direction << 30) | (size << 16) | (ord("V") << 8) | nr


R, W = 2, 1
QUERYCAP = ioc(R, 0, 104)
ENUM_FMT = ioc(R | W, 2, 64)
S_FMT = ioc(R | W, 5, 208)
REQBUFS = ioc(R | W, 8, 20)
QUERYBUF = ioc(R | W, 9, 88)
QBUF = ioc(R | W, 15, 88)
DQBUF = ioc(R | W, 17, 88)
STREAMON = ioc(W, 18, 4)
STREAMOFF = ioc(W, 19, 4)
ENUM_FRAMESIZES = ioc(R | W, 74, 44)
CAPTURE, MMAP = 1, 1
YUYV = struct.unpack("<I", b"YUYV")[0]

path, mode = sys.argv[1], sys.argv[2]
flags = os.O_RDWR | (os.O_NONBLOCK if mode == "poll" else 0)
fd = os.open(path, flags)

cap = bytearray(104)
fcntl.ioctl(fd, QUERYCAP, cap)
assert cap[:8] == b"cellward", bytes(cap[:16])
device_caps = struct.unpack_from("I", cap, 88)[0]
assert device_caps & 1 and device_caps & 0x04000000, hex(device_caps)

desc = bytearray(64)
struct.pack_into("II", desc, 0, 0, CAPTURE)
fcntl.ioctl(fd, ENUM_FMT, desc)
assert struct.unpack_from("I", desc, 44)[0] == YUYV

sizes = []
for index in range(8):
    size = bytearray(44)
    struct.pack_into("II", size, 0, index, YUYV)
    try:
        fcntl.ioctl(fd, ENUM_FRAMESIZES, size)
    except OSError:
        break
    sizes.append(struct.unpack_from("II", size, 12))
assert (640, 480) in sizes, sizes

fmt = bytearray(208)
struct.pack_into("I", fmt, 0, CAPTURE)
struct.pack_into("IIII", fmt, 8, 640, 480, YUYV, 1)
fcntl.ioctl(fd, S_FMT, fmt)
width, height = struct.unpack_from("II", fmt, 8)
size_image = struct.unpack_from("I", fmt, 28)[0]
assert (width, height, size_image) == (640, 480, 640 * 480 * 2)

req = bytearray(20)
struct.pack_into("III", req, 0, 3, CAPTURE, MMAP)
fcntl.ioctl(fd, REQBUFS, req)
count = struct.unpack_from("I", req, 0)[0]
assert count >= 2, count


def buffer(index=0):
    b = bytearray(88)
    struct.pack_into("II", b, 0, index, CAPTURE)
    struct.pack_into("I", b, 60, MMAP)
    return b


maps = []
for index in range(count):
    b = buffer(index)
    fcntl.ioctl(fd, QUERYBUF, b)
    offset, length = struct.unpack_from("I", b, 64)[0], struct.unpack_from("I", b, 72)[0]
    maps.append(
        mmap.mmap(fd, length, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=offset)
    )
    fcntl.ioctl(fd, QBUF, b)

fcntl.ioctl(fd, STREAMON, struct.pack("I", CAPTURE))
start = time.monotonic()
sequences = []
for _ in range(5):
    if mode == "poll":
        waiter = select.poll()
        waiter.register(fd, select.POLLIN)
        assert waiter.poll(5000), "no frame in five seconds"
    b = buffer()
    fcntl.ioctl(fd, DQBUF, b)
    index, used = struct.unpack_from("I", b, 0)[0], struct.unpack_from("I", b, 8)[0]
    sequences.append(struct.unpack_from("I", b, 56)[0])
    assert used == size_image, used
    frame = maps[index][:used]
    assert set(frame[0::2]) == {0x10} and set(frame[1::2]) == {0x80}, "not black"
    fcntl.ioctl(fd, QBUF, b)
elapsed = time.monotonic() - start
fcntl.ioctl(fd, STREAMOFF, struct.pack("I", CAPTURE))
for m in maps:
    m.close()
os.close(fd)
assert sequences == sorted(sequences), sequences
print(f"{mode}: 5 black frames of {width}x{height} in {elapsed:.2f} s, sequence {sequences}")
# The slowest interval listed, 1/5 s: five frames take the most of a second.
assert elapsed > 0.6, elapsed
