# What no container of the real home writes (rust/src/protect.rs, owner
# 2026-09-29): the person's list — the configuration's repository above all,
# whose next rebuild is root's —, git's config and the host's tools; and the
# Nix client's cache, of which such a container gets one of its own. A
# container given a path of the list writes it, from its next start; a place
# the host runs is never given this way. Exec'd by tests/vm.nix in the
# hermetic zone's subtest (`alice`, `machine`, `json`, `STATE` are its).

alice("mkdir -p ~/vmrepo ~/.cache/nix && touch ~/vmrepo/flake.nix ~/.gitconfig ~/.cache/nix/host-made")
alice("cellward protect add ~/vmrepo")
prot_out = alice("cellward protect")
assert "/home/alice/vmrepo" in prot_out, prot_out
prot_st = json.loads(alice("cellward status --json"))
assert {"value": "/home/alice/vmrepo", "source": "local"} in prot_st["settings"]["protected"], prot_st["settings"]
alice("! cellward protect add /etc/nixos")

alice("cellward container create vmprot --home main")
PROT = "cellward run vmherm --container vmprot --"
alice(f"{PROT} sh -c '! touch /home/alice/vmrepo/x'")
alice(f"{PROT} sh -c '! sh -c \"echo x >> /home/alice/.gitconfig\"'")
# The rest of the real home is its own to write, as before.
alice(f"{PROT} sh -c 'touch /home/alice/vmprot-wrote && rm /home/alice/vmprot-wrote'")
# The Nix cache: its own, not the host's.
alice(f"{PROT} sh -c 'test ! -e /home/alice/.cache/nix/host-made && touch /home/alice/.cache/nix/c-made'")
machine.succeed("test ! -e /home/alice/.cache/nix/c-made")


def prot_up():
    st = json.loads(alice("cellward status --json"))
    return any(i.get("id") == "vmprot" for i in st.get("instances", []))


# Given — from its next start; the host's own places never.
alice("cellward container grant vmprot ~/vmrepo")
alice("! cellward container grant vmprot ~/.gitconfig")
alice("! cellward container grant vmprot ~/Documents")
alice("cellward container stop vmprot || true")
retry(lambda _: not prot_up(), timeout=60)
alice(f"{PROT} touch /home/alice/vmrepo/x")
machine.succeed("test -e /home/alice/vmrepo/x")
alice(f"{PROT} sh -c '! sh -c \"echo x >> /home/alice/.gitconfig\"'")

alice("cellward container revoke vmprot ~/vmrepo")
alice("cellward container stop vmprot || true")
retry(lambda _: not prot_up(), timeout=60)
alice(f"{PROT} sh -c '! touch /home/alice/vmrepo/y'")
alice("cellward container stop vmprot || true")
alice("cellward protect rm ~/vmrepo && rm -rf ~/vmrepo ~/.cache/nix/host-made")
