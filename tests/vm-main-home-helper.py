import os
import pathlib
import select
import socket
import sys
import threading
import time


def keep():
    requests = pathlib.Path.home() / "main-home-requests"
    requests.mkdir(exist_ok=True)
    markers = pathlib.Path.home() / "main-home-markers.log"
    results = pathlib.Path.home() / "main-home-results.log"
    seen = set()
    while True:
        for request in requests.iterdir():
            if request.name.startswith(".") or request.name in seen:
                continue
            command = request.read_text().split()
            with markers.open("a") as out:
                out.write(f"{request.name} {os.getpid()}\n")
            seen.add(request.name)
            if not command:
                continue
            try:
                if command[0] == "udp":
                    threading.Thread(
                        target=udp, args=command[1:], daemon=True
                    ).start()
                    answer = "started"
                elif command[0] == "udp_once":
                    udp_once(*command[1:])
                    answer = "sent"
                elif command[0] == "tcp":
                    with socket.create_connection(
                        (command[1], int(command[2])), timeout=3
                    ) as sock:
                        answer = sock.recv(1024).decode().strip()
                else:
                    answer = "unknown-command"
            except Exception as error:
                answer = type(error).__name__
            with results.open("a") as out:
                out.write(f"{request.name} {answer}\n")
        time.sleep(0.05)


def udp(dst, port, tag):
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    n = 0
    while True:
        n += 1
        try:
            sock.sendto(f"{tag}-{n}\n".encode(), (dst, int(port)))
        except OSError:
            pass
        time.sleep(0.15)


def udp_once(dst, port, tag):
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.sendto((tag + "\n").encode(), (dst, int(port)))
    except OSError:
        pass
    sock.close()


def listen(port, log):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(port)))
    while True:
        data, peer = sock.recvfrom(65535)
        with open(log, "a") as out:
            out.write(f"{peer[0]} {data.decode().strip()}\n")


def fakezone(directory, release, log):
    os.makedirs(directory, exist_ok=True)

    def say(what):
        with open(log, "a") as out:
            out.write(what + "\n")

    with open(f"{directory}/config.conf", "w") as out:
        out.write("# test stand-in: attach refuses\n")
    start = open("/proc/self/stat").read().rsplit(")", 1)[1].split()[19]
    boot = open("/proc/sys/kernel/random/boot_id").read().strip()
    with open(f"{directory}/zone.start", "w") as out:
        out.write(f"{start} {boot}\n")
    with open(f"{directory}/zone.pid", "w") as out:
        out.write(f"{os.getpid()}\n")
    path = f"{directory}/bridge.sock"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(4)
    open(f"{directory}/bridge-rule", "w").close()
    open(f"{directory}/ready", "w").close()
    say("up")
    while True:
        conn, _ = srv.accept()
        _, fds, _, _ = socket.recv_fds(conn, 1024, 4)
        say("asked")
        while not os.path.exists(release):
            readable, _, _ = select.select([conn], [], [], 0.2)
            if readable and not conn.recv(1):
                say("hung up")
                break
        else:
            conn.sendall(b"ERR refused by the test\n")
            say("refused")
        for fd in fds:
            os.close(fd)
        conn.close()


globals()[sys.argv[1]](*sys.argv[2:])
