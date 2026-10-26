#!/usr/bin/env python3
"""Windowless synthetic X11 reader, including ICCCM INCR transfers."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys
import time


def main(display, library, output, selection="CLIPBOARD"):
    x, P, L = c.CDLL(library), c.c_void_p, c.c_ulong
    class Property(c.Structure):
        _fields_ = [('type', c.c_int), ('serial', L), ('send_event', c.c_int),
                    ('display', P), ('window', L), ('atom', L), ('time', L), ('state', c.c_int)]
    for name, args, result in [
        ('XOpenDisplay', [c.c_char_p], P), ('XDefaultRootWindow', [P], L),
        ('XCreateSimpleWindow', [P, L, c.c_int, c.c_int, c.c_uint, c.c_uint, c.c_uint, L, L], L),
        ('XSelectInput', [P, L, c.c_long], c.c_int), ('XFlush', [P], c.c_int),
        ('XInternAtom', [P, c.c_char_p, c.c_int], L), ('XConvertSelection', [P, L, L, L, L, L], c.c_int),
        ('XPending', [P], c.c_int), ('XNextEvent', [P, P], c.c_int),
        ('XGetWindowProperty', [P, L, L, c.c_long, c.c_long, c.c_int, L,
                               c.POINTER(L), c.POINTER(c.c_int), c.POINTER(L), c.POINTER(L), c.POINTER(P)], c.c_int),
        ('XFree', [P], c.c_int),
    ]:
        function = getattr(x, name)
        function.argtypes, function.restype = args, result
    display = x.XOpenDisplay(display.encode())
    assert display, 'private X11 display unavailable'
    window = x.XCreateSimpleWindow(display, x.XDefaultRootWindow(display), 0, 0, 1, 1, 0, 0, 0)
    x.XSelectInput(display, window, 1 << 22)
    atom = lambda name: x.XInternAtom(display, name.encode(), 0)
    prop, incr, selection = atom('PRIVATE_PROBE'), atom('INCR'), atom(selection)
    result = {}
    while True:
        for mime in ('text/plain', 'image/png'):
            # Discard completion/deletion events belonging to the last read.
            while x.XPending(display):
                event = (c.c_long * 24)()
                x.XNextEvent(display, c.byref(event))
            x.XConvertSelection(display, selection, atom(mime), prop, window, 0)
            x.XFlush(display)
            body, incremental, complete = bytearray(), False, False
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if not x.XPending(display):
                    time.sleep(.005)
                    continue
                event = (c.c_long * 24)()
                x.XNextEvent(display, c.byref(event))
                kind = c.cast(event, c.POINTER(c.c_int))[0]
                if incremental:
                    notification = Property.from_buffer(event)
                    if kind != 28 or notification.atom != prop or notification.state != 0:
                        continue
                elif kind != 31:
                    continue
                actual, fmt, length, left, data = L(), c.c_int(), L(), L(), P()
                x.XGetWindowProperty(display, window, prop, 0, (64 << 20) // 4, 1, 0,
                                     c.byref(actual), c.byref(fmt), c.byref(length), c.byref(left), c.byref(data))
                try:
                    if actual.value == incr:
                        incremental = True
                        x.XFlush(display)
                        continue
                    if fmt.value == 8 and data:
                        body.extend(c.string_at(data, length.value))
                    assert len(body) <= 64 << 20 and left.value == 0
                    if not incremental or length.value == 0:
                        complete = actual.value != 0
                        break
                    x.XFlush(display)
                finally:
                    if data:
                        x.XFree(data)
            if complete:
                result[mime] = {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                temporary = Path(output + '.tmp')
                temporary.write_text(json.dumps(result))
                temporary.replace(output)
        time.sleep(.1)


if __name__ == '__main__':
    main(*sys.argv[1:])
