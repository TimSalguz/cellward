"""tests/vm.nix, continued: what sits in declared/ is Nix's word only as the
link into the store home-manager makes (docs/THREAT-MODEL.md H6).

Anything that writes the home — a program of the host, a file chooser a
zone's program steers — could put a plain file in
~/.config/vpn-zones/declared/ and speak in Nix's name. Executed by the main
test script with exec(), in its globals (machine, alice).
"""

DECL = "/home/alice/.config/vpn-zones/declared"

with subtest("declared: a plain file or a link out of the store is not Nix's word"):
    # What home-manager made: a link whose end is in the store, and Nix's.
    link = alice(f"readlink {DECL}/hermetic-default").strip()
    real = alice(f"readlink -f {DECL}/hermetic-default").strip()
    assert real.startswith("/nix/store/"), real
    out = alice("cellward status --json")
    assert '"hermetic":{"value":false,"source":"nix"},"ask_again"' in out, out
    # Nobody declared these two: a plain file, and a link out of the store.
    alice(f"printf off > {DECL}/frame-title")
    alice(f"printf leave > /home/alice/vm-entries && ln -s /home/alice/vm-entries {DECL}/user-entries")
    # Nix's own link, replaced by a plain file with the very same word.
    alice(f"rm {DECL}/hermetic-default && printf off > {DECL}/hermetic-default")
    out = alice("cellward status --json")
    assert '"frame_title":{"value":"always","source":"default"}' in out, out
    assert '"user_entries":{"value":"take-over","source":"default"}' in out, out
    assert '"hermetic":{"value":true,"source":"default"},"ask_again"' in out, out
    warned = alice("cellward status --json 2>&1 >/dev/null")
    assert "не от Nix" in warned, warned
    # And not in the way of the CLI, as with nothing declared.
    alice("cellward frame title hover")
    alice("cellward frame title default")
    # Home-manager's link back: Nix's word again.
    alice(f"rm {DECL}/frame-title {DECL}/user-entries /home/alice/vm-entries")
    alice(f"rm {DECL}/hermetic-default && ln -s {link} {DECL}/hermetic-default")
    out = alice("cellward status --json")
    assert '"hermetic":{"value":false,"source":"nix"},"ask_again"' in out, out
