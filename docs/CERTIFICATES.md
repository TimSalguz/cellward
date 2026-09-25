# Trusted certificates per container — design

Russian: [CERTIFICATES.ru.md](CERTIFICATES.ru.md) · Builds on
[CONTAINERS.md](CONTAINERS.md) · Threat model: [LEAK-MODEL.md](LEAK-MODEL.md)

**Status (2026-09-17): implemented for data containers and named sandboxes** —
the CLI (`cellward trust`), the bundle, the environment and the NSS databases,
with the tests of §6 in the smoke and VM tests. Not yet: the GUI dialog, the
declarative option (with the container entity of CONTAINERS phase 1), Java.
The facts in §2 were checked on current nixpkgs binaries; the items marked
*verify* are still open.

## 1. Goal and threat

Some networks require trusting an extra root certificate: a national CA that
state services are signed with, a corporate TLS-inspection root, a test CA.
Whoever holds the private key of a trusted root can **read and alter every TLS
connection** of every program that trusts it: passwords, messages, banking
sessions. So:

> An extra root certificate is trusted by the programs of the containers it
> was added to — **and by nothing else**: not by the host, not by another
> container, not by a later launch of the same program without that container.
> Adding one is loud; removing it is one action.

What this is not: a way to make the host trust a CA (that is NixOS
`security.pki.certificates`, and it is explicitly not what we do), and not a
defence against a CA the host already trusts.

## 2. Where TLS stacks look for trust anchors

A root certificate matters only to the code that reads it. The table is the
inventory the design has to cover. "Bundle" means
`/etc/ssl/certs/ca-certificates.crt`, which on NixOS is a symlink chain ending
in one file of the `nss-cacert` package in the store (the same file is behind
`/etc/ssl/certs/ca-bundle.crt` and `/etc/pki/tls/certs/ca-bundle.crt`).

| consumer | where its anchors come from (NixOS) |
|---|---|
| OpenSSL (nixpkgs) | `NIX_SSL_CERT_FILE` (nixpkgs patch), `SSL_CERT_FILE`/`SSL_CERT_DIR`, then the bundle |
| GnuTLS (GLib/GIO, WebKitGTK, Wine) | the bundle, plus `pkcs11:` system trust — p11-kit |
| p11-kit trust module | compiled path list: `/etc/ssl/trust-source`, the bundle, `/etc/pki/tls/certs/ca-bundle.crt`, `/var/lib/ca-certificates/ca-bundle.pem`, `/etc/ssl/cert.pem` |
| NSS (nixpkgs) | built-in roots module `libnssckbi.so` **is a symlink to `p11-kit-trust.so`** → the list above; plus a per-user/per-profile database (`cert9.db`) |
| Firefox (nixpkgs build) | system NSS → p11-kit → the bundle; the profile's `cert9.db`; enterprise policies |
| Firefox-derived binaries with bundled NSS (e.g. Zen, Tor Browser) | Mozilla's own compiled-in roots; the profile's `cert9.db`; policies |
| Chromium, Chrome, Electron | the Chrome Root Store (built in); locally trusted anchors from the NSS database `~/.pki/nssdb`. Whether the p11-kit roots module counts as local trust: *verify* (expected: no) |
| curl, git, nix (nixpkgs) | `NIX_SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, the bundle |
| Python | `ssl` → OpenSSL; `requests` → `REQUESTS_CA_BUNDLE`; nixpkgs `certifi` → `NIX_SSL_CERT_FILE` |
| Node.js, Bun | compiled-in Mozilla roots + `NODE_EXTRA_CA_CERTS` (read once at startup) |
| Go | `SSL_CERT_FILE`, `SSL_CERT_DIR`, then the bundle |
| Rust `rustls-native-certs` / `webpki-roots` | `SSL_CERT_FILE` and the bundle / **compiled in, unreachable** |
| Java | the JDK's own `cacerts`; `javax.net.ssl.trustStore` |
| .NET, Qt | OpenSSL → as OpenSSL |
| Flatpak apps, Steam runtime, AppImages | their own runtime's `/etc/ssl` — **unreachable** from outside |

Two conclusions shape the design:

1. **On NixOS one file carries most of the trust**: a bind mount of an
   extended bundle over it reaches OpenSSL, GnuTLS, p11-kit and therefore
   system NSS and nixpkgs Firefox, in every language that uses them.
2. **Chromium/Electron and binary Firefox forks need their NSS databases**,
   and those live in the home — which is exactly where a leak to the host would
   happen if the database is not the container's own.

## 3. Design

### 3.1 Storage

- A certificate belongs to a **container**, never to a zone, a program or the
  host. Declared ones come from `containers.<name>.trust.certificates` (a list
  of paths; a public CA certificate in the store is fine); local ones are
  copied into the container's state on `cellward trust add`.
- On adding, the file is parsed and refused unless it is a single PEM or DER
  certificate with `basicConstraints CA:TRUE`. Stored by SHA-256 fingerprint:
  `…/trust/<sha256>.pem`. Parsing and fingerprints use `openssl x509` from the
  manifest (no X.509 or hashing code in the crate).
- Only containers with a home of their own can hold certificates: `private`,
  and `overlay` with the NSS slots guaranteed private (§3.4). **No container
  (the main home) cannot**, because its NSS databases are the host's.

### 3.2 Layer 1 — the bundle (inside the launch's mount namespace)

In `profile-run`, after the home layer and before the program starts
([CONTAINERS.md](CONTAINERS.md) §3.3):

1. build the extended bundle: the bytes of the host's bundle at launch time
   (the file `NIX_SSL_CERT_FILE` or `SSL_CERT_FILE` names, if set, otherwise
   the resolved system bundle) followed by the container's certificates;
   written to a tmpfs mounted over the container's private runtime path;
2. for each existing path of the p11-kit list and the common bundle paths,
   resolve the symlink chain by hand (`sys::link_target`, as for `resolv.conf`,
   [GOTCHAS](GOTCHAS.md) §3) and bind-mount the extended bundle over **each
   distinct target** — on NixOS a single store file;
3. `/etc/ssl/trust-source` is left untouched: this layer only adds.

Binding over the store file also covers programs that name
`${cacert}/etc/ssl/certs/ca-bundle.crt` directly. bwrap binds `/nix/store` and
`/etc` recursively, so a private container sees the same bind.

### 3.3 Layer 2 — the environment

`SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
`GIT_SSL_CAINFO` and `NODE_EXTRA_CA_CERTS` are all set to
**`/etc/ssl/certs/ca-certificates.crt` — the system path**, never to a
container path.

The reason is the most important decision of this document. Environment
variables leak: a program in a container can run `systemctl --user
import-environment` or `dbus-update-activation-environment --all`, and from
then on every user service would inherit them. With the system path the leak
is harmless — outside the container's mount namespace that path is the host's
ordinary bundle. The container-specific **content** comes only from the mount,
and a mount cannot leak.

### 3.4 Layer 3 — NSS databases

For Chromium/Electron (`~/.pki/nssdb`) and for Firefox-family profiles
(`cert9.db` next to `prefs.js` under the known profile roots): `certutil -A -t
"C,," -n "vpn-zones <fingerprint prefix>"`, run by `profile-run` in the
launch's mount namespace before the program starts, from `nss.tools` in the
manifest.

- **A database is written only when it is provably the container's.** Before
  writing, `profile-run` checks that the path lies under an overlay slot it has
  just stacked itself (the list `mount_profile` returns — what was really
  mounted, not what was hoped for), or under the home of a named sandbox. Anything
  else — a profile directory the overlay does not cover (`~/.zen` is not one
  of the XDG slots) — is skipped with a loud warning naming the program and
  suggesting a private home. This is the check that stands between a
  certificate and the host.
- **The trap this avoids.** An overlay slot is only stacked when the host
  directory exists ([GOTCHAS](GOTCHAS.md) §5). On a machine with no `~/.pki`,
  `certutil -d sql:$HOME/.pki/nssdb` inside the container would create the
  database **in the real home**, and the host's Chromium would trust the
  certificate from then on. Containers with trust therefore create the missing
  lower directories (empty, mode 0700) before stacking, and the check above
  catches whatever is still missed.
- Idempotent: a stamp file in the database directory records the fingerprints
  installed; equal stamp → no `certutil` at all.
- The first copy-up forks the container's database from the host's at that
  moment; later host changes are not seen inside. Expected, documented.
- Removal (§3.6) runs `certutil -D` for every stamped nickname; for a `private`
  home it can run from the host directly on the container's directory, for an
  `overlay` home it runs at the next launch (writing the upper layer of a
  mounted overlay from outside is undefined behaviour).

### 3.5 Considered and not used by default

- **Firefox enterprise policies** (`Certificates.Install` in
  `/etc/firefox/policies/policies.json` or `distribution/policies.json`):
  covers fresh profiles, but a bind over an existing `policies.json` replaces
  the user's own policies, and merging means rewriting a file that is not ours.
  Possible later as an explicit per-container option for binary forks.
- **Chromium `CACertificates` policy** in
  `/etc/chromium/policies/managed/`: *verify* availability in the pinned
  Chromium; the same "not our file" concern applies.
- **Java**: opt-in per container, phase 2. A PKCS#12 truststore generated from
  the extended bundle with `openssl pkcs12 -export -nokeys -jdktrust
  anyExtendedKeyUsage`, and `JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=…`
  pointing at a path that exists only inside the container's mount namespace.
  If that variable leaks, Java on the host fails to find the store — TLS
  errors, not trust.
- **Replace mode** ("trust only this CA"): would require shadowing every trust
  source including `trust-source` and cannot remove the Chrome Root Store.
  Out of scope.

### 3.6 Interface

CLI:

```
cellward trust add <container> <file.pem>     # asks for confirmation on a tty
cellward trust list [<container>] [--json]
cellward trust rm <container> <sha256-prefix>
cellward trust reset <container>               # all extra certificates
```

GUI, adding (a file picker, then one dialog):

- subject, issuer, validity, SHA-256 fingerprint, name constraints if any;
- the warning, in words and not in a footnote: «Любой, у кого есть закрытый
  ключ этого сертификата, сможет читать и подменять зашифрованный трафик
  программ контейнера «X»: пароли, переписку, банковские сессии. На хост и в
  другие контейнеры сертификат не попадёт»;
- confirmation by typing the container's name, like zone removal asks twice.

Everywhere a container is shown: a ⚠ marker and "extra root certificate" in
the picker rows, in `cellward container list`, in `status --json`
(`trust.extra[]`) and in `doctor`. Reset is one menu entry: «Сбросить
доверенные сертификаты».

Module (for nix_cm): `containers.<name>.trust = { certificates = [ … ];
acknowledgeRisk = true; nss = true; java = false; }`. An assertion refuses a
non-empty `certificates` without `acknowledgeRisk`.

## 4. Failure behaviour

- The bundle bind (layer 1) fails → **the launch stops** with the reason. A
  program that the user expects to trust a certificate and silently does not
  is a broken launch, and "run without the layer" must not be a code path
  anyone can take by accident.
- An NSS database cannot be proven private → that database is skipped with a
  warning; the launch continues (layer 1 still applies).
- A certificate file is missing or unparsable at launch → the launch stops.

## 5. Where can trust leak now?

- **Host.** The host's bundle is never modified; binds live in the launch's
  mount namespace; environment variables name only the system path (§3.3);
  NSS databases are written only under what this launch proved to be the
  container's own (§3.4).
- **Another container in the same zone.** Every container launch has its own
  mount namespace; nothing is mounted in the zone's.
- **The same program outside the container.** A delegated or brokered launch
  starts in the host's mount namespace and environment — no binds, and the
  variables it might inherit name the system path.
- **Joining a throwaway container** (`--tmp-profile --join`): trust belongs to
  the container, so every tenant gets the same set — none more, none less.
- **A child process that re-enters another zone** goes through delegation or
  the broker and starts outside: no inheritance.
- **Programs we cannot reach** (§2: Flatpak, Steam runtime, AppImages,
  compiled-in roots) do not get the certificate. Not a leak, a limit; `doctor`
  says which programs of a container are of that kind when it can tell.

## 6. Tests

All with a CA generated on the fly (`openssl req -x509 …`) and a server
certificate for `tls.internal` signed by it; nothing real, nothing from the
host. In `tests/vm.nix`, on the machine VM:

1. **Container A trusts it.** A TLS server on loopback inside an offline zone;
   in container A (with the CA) `openssl verify`, `curl --resolve
   tls.internal:8443:127.0.0.1 https://tls.internal:8443` and
   `certutil -L -d sql:$HOME/.pki/nssdb -n …` all succeed; `trust list`
   (p11-kit) shows the CA.
2. **Container B in the same zone does not.** Same commands, all fail.
3. **The host does not.** `openssl verify` and `curl` fail on the host; the
   host's `~/.pki/nssdb` and `/etc/ssl/certs/ca-certificates.crt` hash the same
   before and after.
4. **Environment leak is harmless.** From inside A: `systemctl --user
   import-environment SSL_CERT_FILE NIX_SSL_CERT_FILE`; then `systemd-run
   --user --wait openssl verify …` on the host still fails.
5. **No `~/.pki` on the host.** An overlay container with the CA on a home
   without `~/.pki`: the certificate lands in the container's upper layer and
   the host's home still has no database with it.
6. **Reset.** After `cellward trust reset A`, test 1 fails.
7. **Failure is a refusal.** A container naming a missing certificate file
   does not start.
