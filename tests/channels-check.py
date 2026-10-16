#!/usr/bin/env python3
"""Every route of docs/channels.toml from `program` to an `outside` node:
fails on one with no guard on any of its edges, or with a guarded edge that
names no test, unless the route has a `known` edge (an open item). Prints the
open items it let pass.

    python3 tests/channels-check.py [docs/channels.toml]
"""
import sys
import tomllib


def main(path):
    with open(path, "rb") as f:
        data = tomllib.load(f)
    nodes = {n["id"]: n for n in data.get("node", [])}
    edges = data.get("edge", [])
    errors = []
    for e in edges:
        for end in ("from", "to"):
            if e[end] not in nodes:
                errors.append(f"edge {e['from']} → {e['to']}: no node {e[end]}")
        if e.get("guard") and not e.get("test"):
            errors.append(f"{e['from']} → {e['to']}: guarded ({e['guard']}) but no test")
    out = {}
    for e in edges:
        out.setdefault(e["from"], []).append(e)

    routes = []

    def walk(at, path, seen):
        if nodes.get(at, {}).get("kind") == "outside":
            routes.append(list(path))
            return
        for e in out.get(at, []):
            if e["to"] in seen:
                continue
            path.append(e)
            walk(e["to"], path, seen | {e["to"]})
            path.pop()

    walk("program", [], {"program"})
    known = set()
    for route in routes:
        shown = " → ".join(["program"] + [e["to"] for e in route])
        if any(e.get("known") for e in route):
            known.update(e["known"] for e in route if e.get("known"))
            continue
        if not any(e.get("guard") for e in route):
            errors.append(f"open route: {shown}")
    for item in sorted(known):
        print(f"known open: {item}")
    print(f"{len(routes)} routes, {len(edges)} edges, {len(nodes)} nodes")
    for e in errors:
        print(f"FAIL: {e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/channels.toml"))
