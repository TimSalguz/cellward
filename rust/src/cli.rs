//! `vpn-zone` — the user-facing command line.
//!
//! This was the last big shell script of the project (`module/default.nix`,
//! part 3). What it does has not changed and is not supposed to: the same verbs,
//! the same words in the same messages, the same exit codes — `check` in
//! particular answers with 0/1/2/3 and is meant to be scripted against — and the
//! same files under `~/.local/state/vpn-zones`. The picker and the GUI wrappers
//! are still shell and still call this binary by its profile path, so the two
//! sides have to keep agreeing about all of it.
//!
//! The messages stay in Russian on purpose. They are what the user reads in a
//! terminal, and translating them is a step of its own (ROADMAP M6, gettext with
//! English as the base language); doing it here would have meant a rewrite plus
//! a translation in one commit, with nothing left to compare against.
//!
//! Tool paths come from the manifest ([`crate::tools`]) rather than from `PATH`:
//! part of what is started here runs inside a namespace where `PATH` can be
//! anything at all. The two heavy verbs live next door — `run` in
//! [`crate::launch`], the launch registry in [`crate::registry`].

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use crate::config::WgConfig;
use crate::launch;
use crate::openconnect::{self, OcConfig};
use crate::profile::{exec_command, proc_is_alive, EXIT_NOT_STARTED};
use crate::registry;
use crate::tools::Tools;

/// The manifest is missing or does not match this binary. Not the same thing as
/// a command that failed, hence its own code — and the same "bad invocation"
/// number `vpn-zone-core` uses.
pub const EXIT_TOOLS: u8 = 2;

/// How long `up` and `run` wait for a zone to come up: a hundred tries, a tenth
/// of a second each.
const READY_TRIES: u32 = 100;
const READY_STEP: Duration = Duration::from_millis(100);

const USAGE: &str = "vpn-zone — сетевые зоны с VPN, без root\n\n  vpn-zone add <имя> <файл.conf>   создать зону из конфига AmneziaWG/WireGuard\n                                   или OpenConnect (секция [OpenConnect])\n  vpn-zone add <имя> --system <з.> зона через туннель системной зоны <з.>:\n                                   своего туннеля нет, один VPN — одно\n                                   подключение (конфиг с ключом системной\n                                   зоны становится такой зоной сам)\n  vpn-zone up <имя>                поднять\n  vpn-zone down <имя>              опустить\n  vpn-zone list                    список зон и их состояние\n  vpn-zone status <имя>            подробности (адрес, handshake)\n  vpn-zone status --json           всё состояние машиночитаемо: зоны, контейнеры,\n                                   программы, откуда взято каждое значение\n  vpn-zone status --bar            одна строка JSON для статус-бара (waybar):\n                                   поднятые зоны и живы ли их туннели\n  vpn-zone run <имя> -- <кмд>      запустить программу внутри зоны\n  vpn-zone launch <id> [-- <арг.>] запустить ярлык по id через пикер, как\n                                   щелчок по нему, — для биндов композитора\n  vpn-zone rm <имя>                удалить зону вместе с ярлыками\n  vpn-zone sync                    пересобрать .desktop-ярлыки\n  vpn-zone mode <режим>            как ярлыки работают:\n                                     picker   — один ярлык, спрашивает сеть\n                                                при запуске (по умолчанию)\n                                     per-zone — отдельный ярлык на каждую зону\n                                                (устарел, будет убран)\n                                     both     — и то, и другое (устарел)\n                                     off      — не трогать ярлыки вовсе\n  vpn-zone default <вариант>       что предлагать в пикере для незнакомой\n                                   программы: offline (по умолчанию),\n                                   unconfined (без ограничений: сеть хоста,\n                                   без VPN и изоляции зоны; прежнее имя —\n                                   direct) или имя зоны\n  vpn-zone gc                      убрать зависшие держатели зон, осиротевшую\n                                   обвязку и мёртвые записи\n  vpn-zone perms list|reset <прог.|--all>\n                                   какие доступы к файлам выданы программам\n                                   в песочнице; reset — спросить заново\n  vpn-zone sandbox create|list|rm <имя>\n                                   именованные песочницы: свой дом, общий для\n                                   всех программ, запущенных в этой песочнице\n  vpn-zone run <имя> --sandbox <п> -- <кмд>\n                                   запустить в именованной песочнице\n  vpn-zone run <имя> --fs-sandbox -- <кмд>\n                                   запустить в песочнице файловой системы:\n                                   вместо $HOME — пустой каталог, наружу\n                                   видно только разрешённое, остальное — через\n                                   диалог выбора файла (порталы)\n  vpn-zone run <имя> --tmp-profile -- <кмд>\n                                   запустить в одноразовом контейнере: слой\n                                   создаётся в /tmp и стирается по выходе\n  vpn-zone default-profile <v>     контейнер по умолчанию для всех запусков:\n                                   ask (спрашивать), main (основной),\n                                   own (своя песочница у каждой программы)\n                                   или имя контейнера\n  vpn-zone pins                    какие программы закреплены за сетями\n  vpn-zone forget <прог.|--all>    снять закрепление (снова будет спрашивать)\n  vpn-zone isolate <overlay|off>   свой слой профиля у зоны (overlay — по\n                                   умолчанию). Без него браузер откроет окно\n                                   в уже запущенном процессе, мимо VPN\n  vpn-zone reset-profile <имя>     очистить слой профиля зоны\n  vpn-zone wayland-sandbox on|off  отбирать ли у программ захват экрана,\n                                   чтение буфера в фоне и эмуляцию ввода\n                                   (по умолчанию on; исключения —\n                                   ~/.config/vpn-zones/wayland-allow)\n  vpn-zone check <имя>             прошло ли рукопожатие (жив ли конфиг)\n  vpn-zone watch [--json]          живы ли туннели поднятых зон; при смерти и\n                                   возвращении — уведомление (зовёт таймер)\n  vpn-zone kill <зона>             оборвать зону сейчас: заморозить все её\n                                   программы, опустить зону, убить программы\n                                   (для удалённого доступа, который надо\n                                   прекратить немедленно)\n  vpn-zone journal [--json] [<N>]  последние события: запуски без ограничений\n                                   (unconfined) и решения брокера\n  vpn-zone focused [--json|--bar|--watch]\n                                   в какой сети и контейнере программа окна в\n                                   фокусе (niri, sway); --bar — строка для\n                                   статус-бара, --watch — такая строка при\n                                   каждой смене фокуса\n  vpn-zone window-menu             меню программы окна в фокусе — для бинда\n                                   композитора: закрепить сеть, перезапустить\n                                   с выбором сети, закрыть, оборвать зону\n  vpn-zone doctor [<зона>…] [--json]\n                                   что на деле закрыто: готовность системы и\n                                   проверки изнутри каждой поднятой зоны\n                                   (выходы, маршруты, резолверы, открытые\n                                   каналы); код 1 — есть нарушения\n  vpn-zone hermetic <зона> on|off|default\n                                   герметичная зона: без systemd --user,\n                                   сессионная шина через фильтр, запуск\n                                   наружу через брокер; default — как\n                                   у всех зон\n  vpn-zone hermetic --default on|off\n                                   герметичны ли зоны без своей настройки\n                                   (по умолчанию on, с 2026-09)\n  vpn-zone x11 <зона> on|off       свой X-сервер программам зоны (X хоста в\n                                   зонах недоступен всегда)\n  vpn-zone lock|unlock <имя>       запретить/разрешить программам этой зоны\n                                   запускать что-либо в ДРУГИХ сетях\n                                   (по умолчанию разрешено)\n  vpn-zone trust add <контейнер> <сертификат> [--yes]\n                                   дополнительный корневой сертификат ТОЛЬКО\n                                   для программ этого контейнера (профиль или\n                                   sb:<песочница>): хост и другие контейнеры\n                                   ему не доверяют. Его владелец сможет читать\n                                   TLS-трафик программ контейнера\n  vpn-zone trust list [<контейнер>] [--json]\n  vpn-zone trust rm <контейнер> <начало sha256>\n  vpn-zone trust reset <контейнер> убрать все дополнительные сертификаты\n  vpn-zone container list|show [<контейнер>] [--json]\n                                   контейнеры (профиль или sb:<песочница>):\n                                   их сеть, программы, сертификаты\n  vpn-zone container set <контейнер> network <сеть|ask>\n                                   привязать контейнер к сети: запуск в\n                                   другой сети будет отказом\n  vpn-zone container set <контейнер> x11 on|off\n                                   свой X-сервер в зонах (X хоста в зонах\n                                   недоступен всегда)\n  vpn-zone container assign <программа> <контейнер>\n  vpn-zone container unassign <программа>\n  vpn-zone container grant sb:<песочница> <каталог> [--for 2h]\n  vpn-zone container revoke sb:<песочница> <каталог>\n                                   выдать песочнице каталог настоящего дома\n                                   или диска (/mnt, /media, /run/media, /srv):\n                                   префикс Wine, библиотеку Steam; --for —\n                                   на срок (30s, 15m, 2h, 7d), по истечении\n                                   и при revoke каталог отмонтируется и у\n                                   уже запущенных программ\n  vpn-zone container merge <из> <в> [--yes]\n                                   объединить два контейнера одного вида:\n                                   совпавшее остаётся у <в>, версии из <из>\n                                   кладутся рядом; --yes — согласие принять\n                                   чужие корневые сертификаты\n";

/// Entry point of the `vpn-zone` binary.
pub fn main() -> ExitCode {
    // `args_os`: a launcher can hand a file name through a `%U` field code, and
    // file names are bytes. Refusing to start a program because its argument is
    // not valid Unicode would be a regression against every other launcher.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = args.first().cloned().unwrap_or_default();
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);

    // Help does not need the manifest: somebody who ran the binary without the
    // wrapper needs to be told what this is, not what is missing.
    if matches!(verb.as_bytes(), b"" | b"-h" | b"--help" | b"help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let tools = match Tools::from_env() {
        Ok(tools) => tools,
        Err(e) => {
            eprintln!("vpn-zone: {e}");
            return ExitCode::from(EXIT_TOOLS);
        }
    };

    // The two directories everything else assumes exist.
    for dir in [&tools.state, &tools.profiles] {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("не создать {}: {e}", dir.display());
            return ExitCode::from(1);
        }
    }

    let code = match verb.as_bytes() {
        b"add" => add(&tools, rest),
        b"up" => up(&tools, rest),
        b"down" => down(&tools, rest),
        b"list" => list(&tools),
        b"status" => status(&tools, rest),
        b"lock" => set_lock(&tools, rest, true),
        b"x11" => zone_x11(&tools, rest),
        b"hermetic" => zone_hermetic(&tools, rest),
        // Hidden: the broker's user service runs it (rust/src/broker.rs).
        b"_broker" => crate::broker::serve(&tools),
        b"unlock" => set_lock(&tools, rest, false),
        b"check" => check(&tools, rest),
        b"run" => launch::run(&tools, rest),
        b"launch" => launch_entry(&tools, rest),
        b"gc" => gc(&tools),
        b"doctor" => crate::doctor::run(&tools, rest),
        b"watch" => crate::watch::run(&tools, rest),
        b"journal" => crate::journal::run(&tools, rest),
        b"focused" => crate::focus::run(&tools, rest),
        b"window-menu" => crate::focus::menu(&tools),
        b"kill" => crate::kill::run(&tools, rest),
        b"perms" => perms(&tools, rest),
        b"trust" => trust(&tools, rest),
        b"container" => container(&tools, rest),
        b"sandbox" => sandbox(&tools, rest),
        b"profile" => profile(&tools, rest),
        b"wayland-sandbox" => wayland_sandbox(&tools, rest),
        b"isolate" => isolate(&tools, rest),
        b"reset-profile" => reset_profile(&tools, rest),
        b"rm" => remove(&tools, rest),
        b"sync" => exec_sync(&tools),
        b"mode" => mode(&tools, rest),
        b"default-profile" => default_profile(&tools, rest),
        b"default" => default_network(&tools, rest),
        b"pins" => pins(&tools),
        b"forget" => forget(&tools, rest),
        // Hidden: the tab-completion scripts call it (rust/src/completion.rs).
        // Not in USAGE — a protocol verb, not a command for humans.
        b"_complete" => crate::completion::run(&tools, rest),
        _ => {
            eprintln!("неизвестная команда: {}", verb.to_string_lossy());
            print!("{USAGE}");
            1
        }
    };
    ExitCode::from(code)
}

// --- SHARED PIECES -----------------------------------------------------------

/// The shell's `${1:?message}`: an argument that has to be there and non-empty.
fn required<'a>(args: &'a [OsString], idx: usize, message: &str) -> Option<&'a OsString> {
    match args.get(idx) {
        Some(value) if !value.is_empty() => Some(value),
        _ => {
            eprintln!("{message}");
            None
        }
    }
}

/// Pid of a zone's APP namespace, if it is up.
///
/// `zone.pid` names the namespace programs run in — the one `nsenter` targets.
/// A stale file (the holder was killed, or stopped and its number reused) is
/// not "up": the process has to exist, and be the one that wrote it.
pub fn zone_pid(state: &Path, name: &OsStr) -> Option<i32> {
    let dir = state.join(name);
    let text = fs::read_to_string(dir.join("zone.pid")).ok()?;
    let pid: i32 = text.trim().parse().ok()?;
    // The holder notes when it started: a stopped zone leaves its number
    // behind, and once that number is reused a live process is not the zone.
    // Entering it would put a program into somebody else's namespaces. A
    // holder from before the note counts by its number, as it always did.
    match read_setting(&dir.join("zone.start")).and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(start) => (crate::sys::start_time(pid) == Some(start)).then_some(pid),
        None => proc_is_alive(pid).then_some(pid),
    }
}

/// Wait for the zone to come up, ten seconds at most: the `ready` marker AND
/// a live zone process.
///
/// The bare file is not enough. Stale state (`ready`, `zone.pid`) survives a
/// stop: the holder removes leftovers, but only when the NEXT one starts, and
/// between `systemctl start` and that cleanup the old `ready` is still on
/// disk. Trusting it made `up` after a `down` report "поднята" before the
/// tunnel existed, and made the autostart inside `run` (and the picker) fail
/// instantly — stale `ready`, dead `zone.pid`, «зона не поднимается». Caught
/// by tests/vm.nix on the first run of the systemd path; the smoke test
/// cannot see it (no `systemctl --user` on the CI runner).
pub fn wait_ready(state: &Path, name: &OsStr) -> bool {
    let ready = state.join(name).join("ready");
    let up = || ready.is_file() && zone_pid(state, name).is_some();
    for _ in 0..READY_TRIES {
        if up() {
            return true;
        }
        std::thread::sleep(READY_STEP);
    }
    up()
}

/// `systemctl --user <verb> vpn-zone@<name>.service`, waited for.
///
/// Returns the exit code, or 127 if systemctl itself could not be started —
/// the number a shell reports for that.
pub fn systemctl(tools: &Tools, verb: &str, name: &OsStr) -> u8 {
    let mut unit = OsString::from("vpn-zone@");
    unit.push(name);
    unit.push(".service");
    match Command::new(&tools.systemctl)
        .arg("--user")
        .arg(verb)
        .arg(unit)
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.systemctl.display());
            EXIT_NOT_STARTED
        }
    }
}

/// Read a one-line setting file, the way `$(cat file)` did: trailing newlines
/// dropped, everything else kept. `None` when there is no file.
pub fn read_setting(path: &Path) -> Option<String> {
    let mut text = fs::read_to_string(path).ok()?;
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    Some(text)
}

/// Where the home-manager module puts what is declared in Nix, below the
/// config directory: one file per setting, and `containers/`.
pub const DECLARED_DIR: &str = "declared";

/// A setting of `~/.config/vpn-zones` and where it comes from: the value
/// declared in Nix wins over the local one. `None` when neither is set.
pub fn setting(tools: &Tools, name: &str) -> Option<(String, crate::container::Source)> {
    if let Some(value) = read_setting(&tools.config.join(DECLARED_DIR).join(name)) {
        return Some((value, crate::container::Source::Nix));
    }
    read_setting(&tools.config.join(name)).map(|value| (value, crate::container::Source::Local))
}

/// Write a setting file with no trailing newline (`printf '%s'`), creating
/// `~/.config/vpn-zones` on the way.
///
/// A setting declared in Nix is refused rather than written: the local file
/// would change nothing (the declared one wins) and the command would look
/// like it worked.
fn write_setting(tools: &Tools, name: &str, value: &OsStr) -> Result<(), String> {
    if tools.config.join(DECLARED_DIR).join(name).exists() {
        return Err(format!(
            "«{name}» задано в Nix (programs.vpn-zones) и меняется там"
        ));
    }
    fs::create_dir_all(&tools.config).map_err(|e| format!("{}: {e}", tools.config.display()))?;
    let path = tools.config.join(name);
    fs::write(&path, value.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

/// A name that may become a directory next to other people's data.
///
/// Refuses exactly what is dangerous — a path separator, whitespace, a leading
/// dash or dot — and nothing else. Cyrillic stays Cyrillic: the earlier rule was
/// "latin only", the GUI sanitised a Russian name into a row of dashes, and
/// kdialog takes an argument starting with `-` for an option and closes without
/// a word. (`docs/GOTCHAS.md` §11)
fn safe_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && !bytes.contains(&b'/')
        && !bytes.contains(&b' ')
        && !bytes.starts_with(b"-")
        && !bytes.starts_with(b".")
}

/// A zone name, which is stricter still: it ends up in unit names and in
/// generated `.desktop` files.
fn safe_zone_name(name: &OsStr) -> bool {
    !name.as_bytes().is_empty()
        && name
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Entries of a directory whose names do not start with a dot, sorted — the set
/// and the order of a shell glob.
///
/// Public because the picker and the GUI walk the same directories and have to
/// see them in the same order: a menu that lists the zones differently from
/// `vpn-zone list` would be a bug report waiting to happen.
pub fn visible_entries(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        out.push(entry.path());
    }
    out.sort();
    out
}

/// Disk usage of a directory tree, in bytes, the way `du` counts it: allocated
/// blocks rather than apparent size, directories included, hard links counted
/// once, symlinks not followed.
///
/// Public for the container removal dialog, which shows the same sizes as
/// `vpn-zone profile list`.
pub fn tree_size(path: &Path) -> u64 {
    fn walk(path: &Path, seen: &mut Vec<(u64, u64)>, total: &mut u64) {
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        if meta.nlink() > 1 && !meta.is_dir() {
            let key = (meta.dev(), meta.ino());
            if seen.contains(&key) {
                return;
            }
            seen.push(key);
        }
        *total += meta.blocks() * 512;
        if !meta.is_dir() {
            return;
        }
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            walk(&entry.path(), seen, total);
        }
    }
    let mut seen = Vec::new();
    let mut total = 0;
    walk(path, &mut seen, &mut total);
    total
}

/// `du -h`: powers of 1024, one decimal below ten, rounded UP, no unit letter
/// below a kilobyte.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes}");
    }
    // Ceiling, like du: a byte over 1.0K has to read as 1.1K, never as 1.0K.
    let tenths = (value * 10.0).ceil();
    if tenths < 100.0 {
        format!("{:.1}{}", tenths / 10.0, UNITS[unit])
    } else {
        format!("{}{}", value.ceil(), UNITS[unit])
    }
}

/// Normalise line endings the way `sed 's/\r$//'` did: ONE carriage return at
/// the end of a line, no more.
///
/// Amnezia hands out `.conf` files in the Windows format — verified on a real
/// one, 21 lines with a `\r`. The `\r` ends up at the END OF THE VALUE and the
/// zone dies on its first command: `ip addr add 10.8.1.10/32<CR>` → "inet prefix
/// is expected rather than …". The error looks nonsensical, because a carriage
/// return is invisible in it. (`docs/GOTCHAS.md` §4)
pub fn strip_cr(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for (idx, line) in input.split(|b| *b == b'\n').enumerate() {
        if idx > 0 {
            out.push(b'\n');
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        out.extend_from_slice(line);
    }
    out
}

// --- ZONES -------------------------------------------------------------------

fn add(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let Some(conf) = required(args, 1, "нужен путь к .conf") else {
        return 1;
    };
    // `vpn-zone add <имя> --system <зона>`: a zone through a system zone, with
    // no file to read — the config is two lines and holds no key.
    let system = if conf == "--system" {
        let Some(zone) = required(args, 2, "нужно имя системной зоны") else {
            return 1;
        };
        Some(zone.to_string_lossy().into_owned())
    } else {
        None
    };
    if !safe_zone_name(name) {
        eprintln!("имя только из букв, цифр, - и _");
        return 1;
    }
    // The picker's built-in choices, not zones: a zone called "unconfined" (or
    // "direct", its old name) would never be entered — `vpn-zone run
    // unconfined` is the host's network — and
    // "offline" is the directory the picker creates by itself for the empty
    // zone. (`docs/GOTCHAS.md` §2)
    if launch::is_unconfined_name(&name.to_string_lossy()) || name == launch::OFFLINE {
        eprintln!(
            "«{}» — встроенный вариант пикера, так зону назвать нельзя",
            name.to_string_lossy()
        );
        return 1;
    }
    let conf = Path::new(conf);
    let mut text = if let Some(zone) = &system {
        crate::sysuplink::SysUplinkConfig { zone: zone.clone() }
            .text()
            .into_bytes()
    } else {
        if !conf.is_file() {
            eprintln!("нет файла {}", conf.display());
            return 1;
        }
        match fs::read(conf) {
            Ok(raw) => strip_cr(&raw),
            Err(e) => {
                eprintln!("не читается {}: {e}", conf.display());
                return 1;
            }
        }
    };
    // The parser the zone itself will run on, rather than a `grep` for
    // `[Interface]`: a file that cannot be parsed cannot bring a zone up, and
    // being told so now beats a zone that refuses to start later. Which of the
    // two kinds of zone this is, is one question asked of the same parse — an
    // `[OpenConnect]` section makes it one, anything else is WireGuard.
    let ini = match WgConfig::parse(&text) {
        Ok(ini) => ini,
        Err(e) => {
            eprintln!(
                "{} не похож на конфиг WireGuard/AmneziaWG или OpenConnect: {e}",
                conf.display()
            );
            return 1;
        }
    };
    if openconnect::is_openconnect(&ini) {
        // Checked in full right here, the password file included: a zone that
        // is created now and refuses to come up in a week, with the reason in
        // the journal, is the worst way to learn about a typo.
        match OcConfig::from_ini(&ini).and_then(|cfg| cfg.check_password_file().map(|()| cfg)) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if crate::hostif::is_host_interface(&ini) {
        match crate::hostif::HostIfConfig::from_ini(&ini) {
            Ok(host) => {
                // Only a warning: a VPN the system brings up later, a modem
                // plugged in tomorrow. The zone itself refuses to come up
                // without it.
                if !Path::new("/sys/class/net").join(&host.interface).exists() {
                    eprintln!(
                        "интерфейса {} сейчас нет: зона не поднимется, пока он не появится",
                        host.interface
                    );
                }
                println!(
                    "зона пойдёт наружу через интерфейс хоста {} — сама она трафик не шифрует",
                    host.interface
                );
            }
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if crate::sysuplink::is_system_zone(&ini) {
        match crate::sysuplink::SysUplinkConfig::from_ini(&ini) {
            Ok(sys) => println!(
                "зона пойдёт наружу через туннель системной зоны {} — своего туннеля у неё нет",
                sys.zone
            ),
            Err(e) => {
                eprintln!("{}: {e}", conf.display());
                return 1;
            }
        }
    } else if ini.interface().is_none() {
        eprintln!(
            "{} не похож на конфиг WireGuard/AmneziaWG, OpenConnect, [HostInterface] или \
             [SystemZone]",
            conf.display()
        );
        return 1;
    } else if let Some(key) = ini.interface().and_then(|i| i.get("PrivateKey")) {
        // One VPN, one tunnel: the same key in a user zone next to a system
        // zone makes the server see two devices with one key, and they knock
        // each other off. When the system tier has this VPN already, the user
        // zone goes out through it instead of dialling it a second time.
        if Path::new(crate::sysrun::SOCKET).exists() {
            match crate::sysrun::request_key_owner(key.trim()) {
                Ok(Some(zone)) => {
                    println!(
                        "этот VPN уже поднят системой как зона {zone}: второе подключение \
                         выбивало бы первое, поэтому зона пойдёт наружу через её туннель"
                    );
                    text = crate::sysuplink::SysUplinkConfig { zone }
                        .text()
                        .into_bytes();
                }
                Ok(None) => {}
                // A zone of the system's this user may not use: refused, not
                // dialled a second time behind its back.
                Err(e) if e.contains("already the system zone") => {
                    eprintln!("{e}");
                    return 1;
                }
                Err(e) => eprintln!(
                    "не удалось спросить системный уровень, не поднят ли этот VPN уже там \
                     ({e}) — зона создаётся со своим туннелем"
                ),
            }
        }
    }

    let dir = tools.state.join(name);
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("не создать {}: {e}", dir.display());
        return 1;
    }
    // A copy, not a link: a config with a private key has to survive the
    // original being moved or deleted. Mode 0600 from the start — never a
    // moment where the key is world-readable. (`docs/GOTCHAS.md` §4)
    let target = dir.join("config.conf");
    let _ = fs::remove_file(&target);
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
        .and_then(|mut file| file.write_all(&text));
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", target.display());
        return 1;
    }
    println!("зона {} создана", name.to_string_lossy());
    0
}

fn up(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let code = systemctl(tools, "start", name);
    if code != 0 {
        return code;
    }
    let name_text = name.to_string_lossy();
    if wait_ready(&tools.state, name) {
        println!("зона {name_text} поднята");
        0
    } else {
        eprintln!("зона {name_text} не поднялась — journalctl --user -u vpn-zone@{name_text}");
        1
    }
}

fn down(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let code = systemctl(tools, "stop", name);
    if code != 0 {
        return code;
    }
    println!("зона {} опущена", name.to_string_lossy());
    0
}

fn list(tools: &Tools) -> u8 {
    for dir in visible_entries(&tools.state) {
        if !dir.is_dir() {
            continue;
        }
        let Some(name) = dir.file_name() else {
            continue;
        };
        let state = if zone_pid(&tools.state, name).is_some() {
            "поднята"
        } else {
            "опущена"
        };
        println!("{} — {state}", name.to_string_lossy());
    }
    0
}

fn status(tools: &Tools, args: &[OsString]) -> u8 {
    // The whole state, for configuration tools (`docs/CONTAINERS.md` §9).
    if args.first().is_some_and(|a| a == "--json") {
        println!("{}", crate::status::document(tools));
        return 0;
    }
    // One line for a status bar (waybar's `return-type: json` and the like).
    if args.first().is_some_and(|a| a == "--bar") {
        println!("{}", crate::status::bar(tools));
        return 0;
    }
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let Some(pid) = zone_pid(&tools.state, name) else {
        println!("зона {} не поднята", name.to_string_lossy());
        return 1;
    };
    let code = match Command::new(&tools.nsenter)
        .args(["--preserve-credentials", "-U", "-n", "-m", "-t"])
        .arg(pid.to_string())
        .arg("--")
        .arg(&tools.ip)
        .args(["-br", "-4", "addr", "show"])
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.nsenter.display());
            return EXIT_NOT_STARTED;
        }
    };
    if code != 0 {
        return code;
    }
    // The tunnel's state comes from the mirror the zone writes itself: from the
    // inside, under an ordinary uid, `awg show` has no privileges and says
    // nothing at all. (`docs/GOTCHAS.md` §4)
    if let Ok(mirror) = fs::read_to_string(tools.state.join(name).join("status")) {
        println!();
        print!("{mirror}");
    }
    0
}

fn set_lock(tools: &Tools, args: &[OsString], locked: bool) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let marker = dir.join(launch::NO_ESCAPE);
    let name = name.to_string_lossy();
    if locked {
        if let Err(e) = fs::write(&marker, b"") {
            eprintln!("не записать {}: {e}", marker.display());
            return 1;
        }
        println!(
            "зона {name} заперта: программы из неё не смогут запускать что-либо в других сетях"
        );
    } else {
        let _ = fs::remove_file(&marker);
        println!("зона {name} открыта: запуск из неё в другой сети снова разрешён");
    }
    0
}

/// `vpn-zone hermetic <zone> on|off|default` and
/// `vpn-zone hermetic --default on|off`: `docs/HERMETICITY.md` §7 C — the
/// runtime directory closed, the session bus filtered, the broker as the way
/// out. Takes effect when a zone next comes up; `crate::hermetic` has the
/// order in which the settings win.
fn zone_hermetic(tools: &Tools, args: &[OsString]) -> u8 {
    const USAGE: &str =
        "vpn-zone hermetic <зона> on|off|default\nvpn-zone hermetic --default on|off";
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("{USAGE}");
        return 1;
    };
    if name == "--default" {
        let Some(on) = value.to_str().filter(|v| matches!(*v, "on" | "off")) else {
            eprintln!("{USAGE}");
            return 1;
        };
        if let Err(e) = write_setting(tools, crate::hermetic::DEFAULT_SETTING, OsStr::new(on)) {
            eprintln!("{e}");
            return 1;
        }
        println!(
            "зоны без своей настройки {}герметичны — подействует на зону при её следующем подъёме",
            if on == "on" { "" } else { "не " }
        );
        return 0;
    }
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(crate::hermetic::MARKER);
    if crate::hermetic::zone_setting(&dir, &tools.config, &name).1 == crate::container::Source::Nix
        && crate::hermetic::declared_exception(&tools.config, &name)
    {
        eprintln!("зона {name} — исключение в Nix (hermetic.exceptions) и меняется там");
        return 1;
    }
    let up = zone_pid(&tools.state, OsStr::new(&*name)).is_some();
    let restart = if up {
        format!(" — подействует после перезапуска зоны: vpn-zone down {name} && vpn-zone up {name}")
    } else {
        String::new()
    };
    let written = match value.to_str() {
        Some(v @ ("on" | "off")) => fs::write(&marker, v.as_bytes()),
        Some("default") => match fs::remove_file(&marker) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        _ => {
            eprintln!("{USAGE}");
            return 1;
        }
    };
    if let Err(e) = written {
        eprintln!("не записать {}: {e}", marker.display());
        return 1;
    }
    let (on, source) = crate::hermetic::zone_setting(&dir, &tools.config, &name);
    let from = match source {
        crate::container::Source::Local => "",
        crate::container::Source::Nix => " (умолчание из Nix)",
        crate::container::Source::Default => " (умолчание)",
    };
    if on {
        println!(
            "зона {name} герметична{from}: без systemd --user, сессионная шина через фильтр, \
             запуск наружу — через брокер{restart}"
        );
    } else {
        println!("зона {name} не герметична{from}{restart}");
    }
    0
}

/// `vpn-zone x11 <zone> on|off`: an X server of their own for the programs of a
/// zone (`docs/HERMETICITY.md` §7, A). The host's stays out of reach either way.
fn zone_x11(tools: &Tools, args: &[OsString]) -> u8 {
    let (Some(name), Some(value)) = (args.first(), args.get(1)) else {
        eprintln!("vpn-zone x11 <зона> on|off");
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    let name = name.to_string_lossy();
    let marker = dir.join(crate::x11::ZONE_FLAG);
    match value.to_str() {
        Some("on") => {
            if let Err(e) = fs::write(&marker, b"") {
                eprintln!("не записать {}: {e}", marker.display());
                return 1;
            }
            println!(
                "у программ зоны {name} свой X-сервер (xwayland-satellite); X-сервер хоста по-прежнему недоступен"
            );
            0
        }
        Some("off") => {
            let _ = fs::remove_file(&marker);
            if crate::x11::zone_setting(&tools.state, &tools.config, &name).1
                == crate::container::Source::Nix
            {
                eprintln!("x11 зоны {name} задан в Nix (zoneX11) — выключается там");
                return 1;
            }
            println!("у программ зоны {name} X нет");
            0
        }
        _ => {
            eprintln!("vpn-zone x11 <зона> on|off");
            1
        }
    }
}

/// "Is this config alive at all?" — the short answer, by the fact of a
/// handshake. The exit codes are part of the contract: 0 alive, 1 no handshake,
/// 2 zone down, 3 state unknown.
fn check(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let name_text = name.to_string_lossy();
    if zone_pid(&tools.state, name).is_none() {
        println!("зона {name_text} не поднята");
        return 2;
    }
    // "No handshake" and "no data" are different answers: the mirror is written
    // by the zone itself, and a zone brought up by an older version simply has
    // no such file. Without this check `check` used to declare a live tunnel
    // dead. (`docs/GOTCHAS.md` §4)
    let Ok(mirror) = fs::read_to_string(tools.state.join(name).join("status")) else {
        println!("зона {name_text}: состояние неизвестно — она поднята старой версией,");
        println!("перезапусти её: vpn-zone down {name_text} && vpn-zone up {name_text}");
        return 3;
    };
    match liveness_line(&mirror) {
        Some(line) => {
            println!("зона {name_text}: туннель живой ({line})");
            0
        }
        None => {
            println!("зона {name_text}: рукопожатия нет — конфиг мёртвый или сервер недоступен");
            1
        }
    }
}

/// The line of the status mirror that says the tunnel is alive, whichever
/// backend wrote it.
///
/// A WireGuard zone answers with a handshake; an OpenConnect one has no
/// handshake at all and writes `connected:` instead when its interface is there
/// and up (`crate::zone::oc_mirror`). Writing a fake handshake line into the
/// second kind of file would have kept `check` shorter and told the user
/// something untrue.
pub fn liveness_line(mirror: &str) -> Option<String> {
    handshake_line(mirror).or_else(|| {
        mirror
            .lines()
            .map(str::trim_start)
            .find(|line| line.starts_with("connected:"))
            .map(str::to_owned)
    })
}

/// The "latest handshake" line of a `wg show` mirror, leading spaces trimmed.
///
/// `grep -A20 peer | grep -i 'latest handshake' | head -1`, written down: the
/// line has to belong to a peer block, because the interface block has no
/// handshake in it and a future field named like one must not be read as an
/// answer.
pub fn handshake_line(mirror: &str) -> Option<String> {
    let mut window = 0;
    for line in mirror.lines() {
        if line.contains("peer") {
            window = 21;
        }
        if window == 0 {
            continue;
        }
        window -= 1;
        if line.to_lowercase().contains("latest handshake") {
            return Some(line.trim_start_matches(' ').to_owned());
        }
    }
    None
}

fn reset_profile(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя зоны") else {
        return 1;
    };
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {} нет", name.to_string_lossy());
        return 1;
    }
    if zone_pid(&tools.state, name).is_some() {
        eprintln!(
            "сначала опусти зону: vpn-zone down {}",
            name.to_string_lossy()
        );
        return 1;
    }
    let _ = crate::sys::remove_tree(&dir.join("overlay"));
    println!(
        "слой профиля зоны {} очищен (основной профиль не тронут)",
        name.to_string_lossy()
    );
    0
}

fn remove(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(name) = required(args, 0, "нужно имя") else {
        return 1;
    };
    let name_text = name.to_string_lossy();
    // `unconfined` and `offline` are built-in choices of the picker, not zones:
    // unconfined traffic is the absence of a zone, and the empty one is
    // recreated by the first launch that asks for it. (`docs/GOTCHAS.md` §2)
    // A directory left with the name `unconfined` from before it was taken is
    // a zone all the same, and removable.
    if name == launch::UNCONFINED_ALIAS
        || name == launch::OFFLINE
        || (name == launch::UNCONFINED && !tools.state.join(name).is_dir())
    {
        eprintln!("«{name_text}» — встроенный вариант, его нельзя удалить");
        return 1;
    }
    let dir = tools.state.join(name);
    if !dir.is_dir() {
        eprintln!("зоны {name_text} нет");
        return 1;
    }
    let _ = systemctl(tools, "stop", name);
    if let Err(e) = crate::sys::remove_tree(&dir) {
        eprintln!("не удалить {}: {e}", dir.display());
        return 1;
    }
    // Pins that pointed at this zone go with it: otherwise the program stays
    // bound to a network that no longer exists and fails silently on every
    // launch. (`docs/GOTCHAS.md` §11)
    for sub in [".pinned", ".last"] {
        for file in visible_entries(&tools.state.join(sub)) {
            if read_setting(&file).as_deref() == Some(name_text.as_ref()) {
                let _ = fs::remove_file(&file);
            }
        }
    }
    let code = run_sync(tools);
    if code != 0 {
        return code;
    }
    println!("зона {name_text} удалена");
    0
}

// --- GARBAGE COLLECTION ------------------------------------------------------

/// Sweep up the hung leftovers of zones that were killed rather than stopped.
///
/// The criteria are deliberately EXACT rather than "kill everything orphaned":
/// the first version of this command took a live zone down because it only
/// looked at `zone.pid`. So: processes under systemd (`vpn-zone@…`) are not
/// touched at all — the unit owns them; a pasta is killed only when the netns it
/// serves is dead, and its number is right there in its command line; other
/// people's sandboxes (bwrap) are left alone, there are programs in them.
/// (`docs/GOTCHAS.md` §2)
fn gc(tools: &Tools) -> u8 {
    let mut killed = 0;
    for pid in processes_named("pasta") {
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
        if cgroup.contains("vpn-zone@") {
            continue;
        }
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let Some(target) = netns_pid(&cmdline) else {
            continue;
        };
        if proc_is_alive(target) {
            continue;
        }
        // SAFETY: kill(2) with a pid we read out of /proc and a plain signal
        // number; the worst a race can do is deliver TERM to nothing.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            killed += 1;
        }
    }

    let running = tools.state.join(".running");
    let mut cleaned = registry::sweep_dead(&running, &|pid| registry::alive(&running, pid));
    registry::sweep_started(&running);

    // Abandoned throwaway containers. Their home is erased behind the last
    // tenant, but a hard kill leaves the directory. Judged by live PIDs in the
    // registry and not by the registry directory existing: after a hard kill
    // that directory stays around full of dead records, and the older check kept
    // the garbage in /tmp forever. (`docs/GOTCHAS.md` §5)
    // Below the state directory, and in /tmp, where they lived before
    // (`docs/LEAK-MODEL.md` §15).
    for base in crate::launch::throwaway_bases(&tools.state) {
        for dir in visible_entries(&base) {
            let Some(name) = dir.file_name() else {
                continue;
            };
            if !name.as_bytes().starts_with(b"vpn-profile-") || !dir.is_dir() {
                continue;
            }
            let regdir = running.join(name);
            if registry::any_live(&regdir, &|pid| registry::alive(&running, pid)) {
                continue;
            }
            let _ = crate::sys::remove_tree(&dir);
            let _ = crate::sys::remove_tree(&regdir);
            cleaned += 1;
        }
    }

    println!("остановлено зависших выходов в сеть: {killed}, подчищено записей: {cleaned}");
    0
}

/// Pids whose `comm` is exactly this — `pgrep -x`, without the process table
/// tool.
fn processes_named(name: &str) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim_end_matches('\n') == name {
            out.push(pid);
        }
    }
    out.sort_unstable();
    out
}

/// The pid out of the first `/proc/<pid>/ns/net` in a command line.
///
/// That is how a stray pasta is recognised: it is attached to a namespace from
/// the outside, and in the gateway layout that namespace is the zone's UPLINK.
/// (`docs/GOTCHAS.md` §2)
pub fn netns_pid(cmdline: &[u8]) -> Option<i32> {
    const PREFIX: &[u8] = b"/proc/";
    const SUFFIX: &[u8] = b"/ns/net";
    for start in 0..cmdline.len() {
        if !cmdline[start..].starts_with(PREFIX) {
            continue;
        }
        let digits_at = start + PREFIX.len();
        let end = digits_at
            + cmdline[digits_at..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
        if end > digits_at && cmdline[end..].starts_with(SUFFIX) {
            return std::str::from_utf8(&cmdline[digits_at..end])
                .ok()
                .and_then(|digits| digits.parse().ok());
        }
    }
    None
}

// --- PERMISSIONS, SANDBOXES, CONTAINERS --------------------------------------

fn perms(tools: &Tools, args: &[OsString]) -> u8 {
    let dir = tools.config.join("fs-perms");
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"list" => {
            let files: Vec<PathBuf> = visible_entries(&dir)
                .into_iter()
                .filter(|f| f.is_file())
                .collect();
            if files.is_empty() {
                println!("доступы никому не выдавались");
                return 0;
            }
            for file in files {
                let text = fs::read_to_string(&file)
                    .unwrap_or_default()
                    .replace('\n', " ");
                let shown = if text.is_empty() {
                    "ничего"
                } else {
                    &text
                };
                println!(
                    "{} → {shown}",
                    file.file_name().unwrap_or_default().to_string_lossy()
                );
            }
            0
        }
        b"reset" => {
            let Some(what) = required(rest, 0, "имя программы или --all") else {
                return 1;
            };
            if what == "--all" {
                let _ = crate::sys::remove_tree(&dir);
                println!("сброшено для всех — при следующем запуске спросит заново");
            } else {
                let _ = fs::remove_file(dir.join(what));
                println!("сброшено для {}", what.to_string_lossy());
            }
            0
        }
        _ => {
            eprintln!("vpn-zone perms list|reset <программа|--all>");
            1
        }
    }
}

/// Named sandboxes. NOT containers: a container is a layer over your home (you
/// see everything, only the data is split), a sandbox has a home of its own and
/// it is empty. Hence the separate directory.
fn sandbox(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"create" => {
            let Some(name) = required(rest, 0, "нужно имя песочницы") else {
                return 1;
            };
            if !safe_name(name) {
                eprintln!("в имени нельзя: / пробел, и оно не должно начинаться с - или .");
                return 1;
            }
            let home = tools.sandboxes.join(name).join("home");
            if let Err(e) = fs::create_dir_all(&home) {
                eprintln!("не создать {}: {e}", home.display());
                return 1;
            }
            println!(
                "песочница {} создана (свой пустой дом, доступ наружу спросится при запуске)",
                name.to_string_lossy()
            );
            0
        }
        b"list" => {
            let dirs: Vec<PathBuf> = visible_entries(&tools.sandboxes)
                .into_iter()
                .filter(|d| d.is_dir())
                .collect();
            if dirs.is_empty() {
                println!("песочниц нет. Создать: vpn-zone sandbox create <имя>");
                return 0;
            }
            for dir in dirs {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let perms = fs::read_to_string(dir.join("perms"))
                    .unwrap_or_default()
                    .replace('\n', " ");
                let perms = if perms.is_empty() {
                    "ничего"
                } else {
                    &perms
                };
                let size = human_size(tree_size(&dir));
                match name.strip_prefix("app-") {
                    Some(app) => {
                        println!("{name} — своя песочница программы {app}, {size}, доступ: {perms}")
                    }
                    None => println!("{name} — {size}, доступ: {perms}"),
                }
            }
            0
        }
        b"rm" => {
            let Some(name) = required(rest, 0, "нужно имя песочницы") else {
                return 1;
            };
            let dir = tools.sandboxes.join(name);
            if !dir.is_dir() {
                eprintln!("песочницы {} нет", name.to_string_lossy());
                return 1;
            }
            if let Err(e) = crate::sys::remove_tree(&dir) {
                eprintln!("не удалить {}: {e}", dir.display());
                return 1;
            }
            println!(
                "песочница {} удалена вместе со своим домом",
                name.to_string_lossy()
            );
            0
        }
        _ => {
            eprintln!("vpn-zone sandbox create|list|rm <имя>");
            1
        }
    }
}

fn profile(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"create" => {
            let Some(name) = required(rest, 0, "нужно имя профиля") else {
                return 1;
            };
            if !safe_name(name) {
                eprintln!("в имени нельзя: / пробел, и оно не должно начинаться с - или .");
                return 1;
            }
            let dir = tools.profiles.join(name);
            if let Err(e) = fs::create_dir_all(&dir) {
                eprintln!("не создать {}: {e}", dir.display());
                return 1;
            }
            println!(
                "профиль {} создан (пустой слой поверх твоего ~/)",
                name.to_string_lossy()
            );
            0
        }
        b"list" => {
            let dirs: Vec<PathBuf> = visible_entries(&tools.profiles)
                .into_iter()
                .filter(|d| d.is_dir())
                .collect();
            if dirs.is_empty() {
                println!("профилей нет. Создать: vpn-zone profile create <имя>");
                return 0;
            }
            let running = tools.state.join(".running");
            for dir in dirs {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let size = human_size(tree_size(&dir));
                // Who has it open, from the shared launch registry — the same
                // one the network-conflict warning reads.
                match registry::live_zone(&running.join(&name), &|pid| {
                    registry::alive(&running, pid)
                }) {
                    Some(zone) => println!("{name} — открыт в сети {zone} ({size})"),
                    None => println!("{name} — свободен ({size})"),
                }
            }
            0
        }
        b"rm" => {
            let Some(name) = required(rest, 0, "нужно имя профиля") else {
                return 1;
            };
            let dir = tools.profiles.join(name);
            if !dir.is_dir() {
                eprintln!("профиля {} нет", name.to_string_lossy());
                return 1;
            }
            if let Err(e) = crate::sys::remove_tree(&dir) {
                eprintln!("не удалить {}: {e}", dir.display());
                return 1;
            }
            println!("профиль {} удалён", name.to_string_lossy());
            0
        }
        _ => {
            eprintln!("vpn-zone profile create|list|rm <имя>");
            1
        }
    }
}

// --- TRUSTED CERTIFICATES ----------------------------------------------------

/// `vpn-zone trust …`: extra root certificates of ONE container
/// (`docs/CERTIFICATES.md`). The layer itself is laid down at launch time by
/// `profile-run` (`crate::trust`); this is the storage and the loud part.
fn trust(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    match sub.as_bytes() {
        b"add" => trust_add(tools, rest),
        b"list" => trust_list(tools, rest),
        b"rm" => trust_remove(tools, rest, false),
        b"reset" => trust_remove(tools, rest, true),
        _ => {
            eprintln!("vpn-zone trust add|list|rm|reset <контейнер> …");
            1
        }
    }
}

/// A container a certificate can belong to.
struct TrustTarget {
    /// As the user named it: a profile name, or `sb:<sandbox>`.
    shown: String,
    /// The container's own directory; the certificates live in `trust/` there.
    dir: PathBuf,
    /// A named sandbox's home on disk: its NSS databases can be brought in line
    /// right away, from here. `None` for a data container, whose databases sit
    /// under an overlay and are only touched from inside a launch.
    home: Option<PathBuf>,
}

impl TrustTarget {
    fn trust_dir(&self) -> PathBuf {
        self.dir.join(crate::trust::DIR)
    }
}

/// `sb:<name>` is a named sandbox, anything else a data container. The main
/// profile is neither: its NSS databases are the host's, and a certificate
/// there would be the host's too.
fn trust_target(tools: &Tools, name: &OsStr) -> Result<TrustTarget, String> {
    let text = name.to_string_lossy().into_owned();
    if let Some(sandbox) = text.strip_prefix("sb:") {
        if !safe_name(OsStr::new(sandbox)) {
            return Err(format!("нет такой песочницы: {text}"));
        }
        let dir = tools.sandboxes.join(sandbox);
        if !dir.is_dir() {
            return Err(format!(
                "песочницы {sandbox} нет — создай: vpn-zone sandbox create {sandbox}"
            ));
        }
        return Ok(TrustTarget {
            home: Some(dir.join("home")),
            shown: text,
            dir,
        });
    }
    if !safe_name(name) || text == registry::MAIN {
        return Err(format!(
            "«{text}» — не контейнер: основной профиль общий с хостом, и сертификат в нём был бы сертификатом хоста"
        ));
    }
    let dir = tools.profiles.join(name);
    if !dir.is_dir() {
        return Err(format!(
            "контейнера {text} нет — создай: vpn-zone profile create {text}"
        ));
    }
    Ok(TrustTarget {
        shown: text,
        dir,
        home: None,
    })
}

/// `openssl x509 … -noout -fingerprint -sha256 -subject -issuer -enddate -ext
/// basicConstraints` on a certificate file.
pub fn certificate_info(
    tools: &Tools,
    file: &Path,
    inform: &str,
) -> Result<crate::trust::CertInfo, String> {
    let out = Command::new(&tools.openssl)
        .args(["x509", "-inform", inform, "-in"])
        .arg(file)
        .args([
            "-noout",
            "-fingerprint",
            "-sha256",
            "-subject",
            "-issuer",
            "-enddate",
            "-ext",
            "basicConstraints",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("не запустить {}: {e}", tools.openssl.display()))?;
    if !out.status.success() {
        return Err(format!(
            "{} не похож на сертификат X.509: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    crate::trust::parse_x509_text(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| format!("openssl не назвал отпечаток {}", file.display()))
}

fn trust_add(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(container) = required(args, 0, "нужен контейнер: имя профиля или sb:<песочница>")
    else {
        return 1;
    };
    let Some(file) = required(args, 1, "нужен файл сертификата (PEM или DER)")
    else {
        return 1;
    };
    let yes = args.iter().skip(2).any(|a| a == "--yes");
    let target = match trust_target(tools, container) {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let file = Path::new(file);
    let raw = match fs::read(file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("не читается {}: {e}", file.display());
            return 1;
        }
    };
    // One certificate per file, checked before anything is run: a bundle added
    // "as a certificate" would smuggle in every root inside it.
    let pems = crate::trust::count_pem_certs(&raw);
    if pems > 1 {
        eprintln!(
            "в {} сертификатов: {pems} — добавляй по одному, иначе в контейнер уехал бы каждый корень из этого файла",
            file.display()
        );
        return 1;
    }
    let inform = if pems == 1 { "PEM" } else { "DER" };
    let info = match certificate_info(tools, file, inform) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    if !info.is_ca {
        eprintln!(
            "{} — не сертификат удостоверяющего центра (нет basicConstraints CA:TRUE): корнем доверия он быть не может",
            file.display()
        );
        return 1;
    }
    let pem = match Command::new(&tools.openssl)
        .args(["x509", "-inform", inform, "-in"])
        .arg(file)
        .args(["-outform", "PEM"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() && crate::trust::count_pem_certs(&out.stdout) == 1 => {
            out.stdout
        }
        Ok(out) => {
            eprintln!(
                "openssl не перевёл {} в PEM: {}",
                file.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return 1;
        }
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.openssl.display());
            return 1;
        }
    };

    println!("Сертификат:    {}", info.subject);
    println!("Издатель:      {}", info.issuer);
    println!("Действует до:  {}", info.not_after);
    println!("SHA-256:       {}", info.sha256);
    println!();
    println!(
        "ВНИМАНИЕ. Любой, у кого есть закрытый ключ этого сертификата, сможет читать и подменять \
         зашифрованный трафик программ контейнера «{}»: пароли, переписку, банковские сессии. На \
         хост и в другие контейнеры сертификат не попадёт.",
        target.shown
    );
    if !yes {
        // SAFETY: isatty(3) takes no pointers.
        if unsafe { libc::isatty(0) } != 1 {
            eprintln!("нужно подтверждение: запусти в терминале или добавь --yes");
            return 1;
        }
        print!("Чтобы добавить, введи имя контейнера ({}): ", target.shown);
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() || answer.trim() != target.shown {
            println!("не подтверждено — ничего не добавлено");
            return 1;
        }
    }

    let dir = target.trust_dir();
    let path = dir.join(format!("{}.pem", info.sha256));
    if let Err(e) = fs::create_dir_all(&dir).and_then(|()| fs::write(&path, &pem)) {
        eprintln!("не записать {}: {e}", path.display());
        return 1;
    }
    println!(
        "сертификат {} добавлен в контейнер {}: программы, запущенные в нём с этой минуты, ему \
         доверяют; уже запущенные — нет",
        &info.sha256[..16],
        target.shown
    );
    0
}

fn trust_list(tools: &Tools, args: &[OsString]) -> u8 {
    let json = args.iter().any(|a| a == "--json");
    let named: Vec<&OsString> = args.iter().filter(|a| *a != "--json").collect();
    let targets: Vec<TrustTarget> = match named.first() {
        Some(name) => match trust_target(tools, name) {
            Ok(target) => vec![target],
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        },
        None => {
            let profiles = visible_entries(&tools.profiles).into_iter().map(|dir| {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                TrustTarget {
                    shown: name,
                    dir,
                    home: None,
                }
            });
            let sandboxes = visible_entries(&tools.sandboxes).into_iter().map(|dir| {
                let name = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                TrustTarget {
                    shown: format!("sb:{name}"),
                    home: Some(dir.join("home")),
                    dir,
                }
            });
            profiles
                .chain(sandboxes)
                .filter(|t| t.trust_dir().is_dir())
                .collect()
        }
    };

    let mut rows: Vec<(String, crate::trust::CertInfo)> = Vec::new();
    for target in &targets {
        for cert in crate::trust::stored(&target.trust_dir()) {
            // A certificate openssl cannot read any more is still listed, by its
            // fingerprint: hiding it would hide that it is trusted.
            let info =
                certificate_info(tools, &cert.path, "PEM").unwrap_or(crate::trust::CertInfo {
                    sha256: cert.sha256.clone(),
                    ..crate::trust::CertInfo::default()
                });
            rows.push((target.shown.clone(), info));
        }
    }

    if json {
        let items: Vec<String> = rows
            .iter()
            .map(|(container, info)| {
                format!(
                    "{{\"container\":{},\"sha256\":{},\"subject\":{},\"issuer\":{},\"not_after\":{},\"source\":\"local\"}}",
                    crate::status::string(container),
                    crate::status::string(&info.sha256),
                    crate::status::string(&info.subject),
                    crate::status::string(&info.issuer),
                    crate::status::string(&info.not_after)
                )
            })
            .collect();
        println!("{{\"schema_version\":1,\"trust\":[{}]}}", items.join(","));
        return 0;
    }
    if rows.is_empty() {
        println!("дополнительных корневых сертификатов нет ни у одного контейнера");
        return 0;
    }
    for (container, info) in rows {
        let subject = if info.subject.is_empty() {
            "(не читается)".to_owned()
        } else {
            info.subject
        };
        println!(
            "{container}: {} — {subject}, до {}",
            &info.sha256[..16],
            info.not_after
        );
    }
    0
}

/// `rm <container> <prefix>` and `reset <container>`.
fn trust_remove(tools: &Tools, args: &[OsString], all: bool) -> u8 {
    let Some(container) = required(args, 0, "нужен контейнер: имя профиля или sb:<песочница>")
    else {
        return 1;
    };
    let target = match trust_target(tools, container) {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let stored = crate::trust::stored(&target.trust_dir());
    let doomed: Vec<&crate::trust::Stored> = if all {
        stored.iter().collect()
    } else {
        let Some(prefix) = required(
            args,
            1,
            "нужно начало отпечатка SHA-256 (vpn-zone trust list)",
        ) else {
            return 1;
        };
        let prefix = prefix.to_string_lossy().to_ascii_lowercase();
        let matching: Vec<&crate::trust::Stored> = stored
            .iter()
            .filter(|c| c.sha256.starts_with(&prefix))
            .collect();
        match matching.len() {
            0 => {
                eprintln!("у контейнера {} нет сертификата {prefix}…", target.shown);
                return 1;
            }
            1 => matching,
            n => {
                eprintln!("«{prefix}» подходит к {n} сертификатам — укажи больше символов");
                return 1;
            }
        }
    };
    for cert in &doomed {
        if let Err(e) = fs::remove_file(&cert.path) {
            eprintln!("не удалить {}: {e}", cert.path.display());
            return 1;
        }
    }
    // A named sandbox's databases are its own directory on disk: bring them in
    // line now. A data container's sit under its overlay, and the next launch
    // does it from inside — the (possibly empty) trust directory is what makes
    // that launch lay the layer down.
    match &target.home {
        Some(home) => {
            for warning in crate::trust::sync_home(&tools.certutil, &target.trust_dir(), home) {
                eprintln!("{warning}");
            }
            println!(
                "у контейнера {} убрано сертификатов: {}",
                target.shown,
                doomed.len()
            );
        }
        None => println!(
            "у контейнера {} убрано сертификатов: {} — из его баз NSS они уйдут при следующем запуске программы в нём",
            target.shown,
            doomed.len()
        ),
    }
    0
}

// --- LAUNCH BY ID -------------------------------------------------------------

/// `vpn-zone launch <id> [-- <arguments>]`: a launcher entry started through the
/// picker by its id, the way a click on it would start — for compositor key
/// bindings and scripts, which otherwise start the program itself, uncontained
/// (`docs/CONTAINERS.md` §5.1).
fn launch_entry(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(id) = required(
        args,
        0,
        "нужен id ярлыка: имя .desktop-файла без расширения",
    ) else {
        return 1;
    };
    let id = id.to_string_lossy().into_owned();
    let extra: &[OsString] = match args.iter().position(|a| a == "--") {
        Some(at) => &args[at + 1..],
        None if args.len() > 1 => {
            eprintln!("аргументы программы — после --: vpn-zone launch {id} -- <аргументы>");
            return 1;
        }
        None => &[],
    };
    if id.starts_with(crate::desktop::PREFIX) {
        eprintln!("{id} — служебный ярлык vpn-zones: его запускают как есть, не через пикер");
        return 1;
    }
    let dirs = crate::desktop::source_dirs(&tools.home);
    let Some((file, groups)) = crate::desktop::find_entry(&dirs, &tools.home, &tools.state, &id)
    else {
        eprintln!("ярлыка {id} нет ни в одном каталоге приложений");
        return 1;
    };
    let Some(entry) = crate::desktop::desktop_entry(&groups) else {
        return 1;
    };
    let (cmd, used) = crate::desktop::expand_exec(entry, &file, extra);
    if cmd.is_empty() {
        eprintln!("у ярлыка {id} нет Exec — запускать нечего");
        return 1;
    }
    if !extra.is_empty() && !used {
        eprintln!("ярлык {id} не принимает аргументов (в Exec нет %u, %f…) — они не переданы");
    }
    let mut argv: Vec<OsString> = vec![
        tools.picker.clone().into(),
        "--id".into(),
        crate::desktop::stable_key(&id).into(),
    ];
    if let Some(name) = entry.get("Name").filter(|n| !n.is_empty()) {
        argv.push("--label".into());
        argv.push(name.into());
    }
    argv.push("--".into());
    argv.extend(cmd);
    if std::env::var_os(launch::ENV_DRYRUN).is_some_and(|v| !v.is_empty()) {
        let words: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        println!("{}", words.join(" "));
        return 0;
    }
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.picker.display());
    EXIT_NOT_STARTED
}

// --- CONTAINERS --------------------------------------------------------------

/// `vpn-zone container …`: containers as identities (`docs/CONTAINERS.md`).
fn container(tools: &Tools, args: &[OsString]) -> u8 {
    let sub = args
        .first()
        .cloned()
        .unwrap_or_else(|| OsString::from("list"));
    let rest: &[OsString] = args.get(1..).unwrap_or(&[]);
    let json = rest.iter().any(|a| a == "--json");
    let yes = rest.iter().any(|a| a == "--yes");
    let words: Vec<String> = rest
        .iter()
        .filter(|a| *a != "--json" && *a != "--yes")
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    match sub.as_bytes() {
        b"list" => container_list(tools, json),
        b"show" => {
            let Some(selector) = words.first() else {
                eprintln!("нужен контейнер: имя профиля или sb:<песочница>");
                return 1;
            };
            let Some(c) = crate::container::load(tools, selector) else {
                eprintln!("контейнера {selector} нет");
                return 1;
            };
            if json {
                println!(
                    "{{\"schema_version\":{},\"container\":{}}}",
                    crate::status::SCHEMA_VERSION,
                    crate::status::container(tools, &c)
                );
            } else {
                print_container(tools, &c);
            }
            0
        }
        b"set" => {
            let (Some(selector), Some(key), Some(value)) =
                (words.first(), words.get(1), words.get(2))
            else {
                eprintln!("vpn-zone container set <контейнер> network <сеть|ask> | x11 on|off");
                return 1;
            };
            if key == "x11" {
                let on = match value.as_str() {
                    "on" => true,
                    "off" => false,
                    _ => {
                        eprintln!("x11: on или off");
                        return 1;
                    }
                };
                return match crate::container::set_x11(tools, selector, on) {
                    Ok(()) if on => {
                        println!(
                            "у контейнера {selector} в зонах свой X-сервер (xwayland-satellite); \
                             X-сервер хоста по-прежнему недоступен"
                        );
                        0
                    }
                    Ok(()) => {
                        println!("у контейнера {selector} в зонах X нет");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                };
            }
            if key != "network" {
                eprintln!("у контейнера меняются network и x11");
                return 1;
            }
            let Some(network) = crate::container::Network::parse(value) else {
                eprintln!("«{value}» — не имя сети");
                return 1;
            };
            if let crate::container::Network::Named(name) = &network {
                if !network_exists(tools, name) {
                    eprintln!("сети {name} нет — есть unconfined, offline и зоны из vpn-zone list");
                    return 1;
                }
            }
            match crate::container::set_network(tools, selector, &network) {
                Ok(()) => {
                    match &network {
                        crate::container::Network::Ask => {
                            println!("контейнер {selector} больше не привязан: сеть спрашивается при запуске")
                        }
                        crate::container::Network::Named(name) => println!(
                            "контейнер {selector} привязан к сети {name}: его программы запускаются только в ней"
                        ),
                    }
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        b"assign" => {
            let (Some(app), Some(selector)) = (words.first(), words.get(1)) else {
                eprintln!("vpn-zone container assign <программа> <контейнер>");
                return 1;
            };
            if crate::container::load(tools, selector).is_none() {
                eprintln!("контейнера {selector} нет");
                return 1;
            }
            if let Some(owner) = crate::container::declared_owner(tools, app) {
                if &owner != selector {
                    eprintln!("программа {app} назначена контейнеру {owner} в Nix — меняется там");
                    return 1;
                }
            }
            let dir = tools.state.join(".pinnedprofile");
            let path = dir.join(crate::desktop::stable_key(app));
            if let Err(e) = fs::create_dir_all(&dir).and_then(|()| fs::write(&path, selector)) {
                eprintln!("не записать {}: {e}", path.display());
                return 1;
            }
            println!("программа {app} назначена контейнеру {selector}");
            0
        }
        b"unassign" => {
            let Some(app) = words.first() else {
                eprintln!("vpn-zone container unassign <программа>");
                return 1;
            };
            let _ = fs::remove_file(
                tools
                    .state
                    .join(".pinnedprofile")
                    .join(crate::desktop::stable_key(app)),
            );
            match crate::container::declared_owner(tools, app) {
                Some(owner) => println!(
                    "локальное назначение {app} снято, но в Nix программа назначена контейнеру {owner}"
                ),
                None => println!("программа {app} больше не назначена контейнеру"),
            }
            0
        }
        b"expire" => crate::grants::expire(tools),
        b"grant" | b"revoke" => {
            let grant = sub == "grant";
            const USAGE: &str =
                "vpn-zone container grant sb:<песочница> <каталог> [--for 30m|2h|7d]\n\
                 vpn-zone container revoke sb:<песочница> <каталог>";
            let (Some(selector), Some(path)) = (words.first(), words.get(1)) else {
                eprintln!("{USAGE}");
                return 1;
            };
            let term = match (words.get(2).map(String::as_str), words.get(3)) {
                (None, _) => None,
                (Some("--for"), Some(term)) if grant && words.len() == 4 => {
                    match crate::grants::parse_term(term) {
                        Some(secs) => Some(secs),
                        None => {
                            eprintln!("срок — число и единица: 30s, 15m, 2h, 7d (не больше 366d)");
                            return 1;
                        }
                    }
                }
                _ => {
                    eprintln!("{USAGE}");
                    return 1;
                }
            };
            let until = term.map(|secs| crate::container::now() + secs);
            match crate::container::set_path(tools, selector, path, grant, until) {
                Ok(path) if grant => {
                    let shown = path.to_string_lossy();
                    let until_text = until.map(crate::journal::utc).unwrap_or_default();
                    if let Err(e) = crate::journal::append(
                        &tools.state,
                        "grant",
                        &[
                            ("container", selector.as_str()),
                            ("path", &*shown),
                            ("until", until_text.as_str()),
                        ],
                    ) {
                        eprintln!("журнал: {e}");
                    }
                    let term_text = match term {
                        None => String::new(),
                        Some(secs) => {
                            let timer = if crate::grants::schedule_expiry(tools, secs) {
                                ""
                            } else {
                                " (таймер не поставить: уже запущенные программы сохранят \
                                 доступ до `vpn-zone container expire`, новые его не получат)"
                            };
                            format!(
                                " до {} UTC{timer}",
                                until_text.replace(['T', 'Z'], " ").trim_end()
                            )
                        }
                    };
                    println!(
                        "{shown} выдан контейнеру {selector}{term_text}: его программы видят и \
                         меняют там всё, и то, что они туда положат, увидят программы вне контейнера"
                    );
                    0
                }
                Ok(path) => {
                    let shown = path.to_string_lossy();
                    let (detached, failed) = crate::grants::detach_live(tools, selector, &path);
                    if let Err(e) = crate::journal::append(
                        &tools.state,
                        "revoke",
                        &[
                            ("container", selector.as_str()),
                            ("path", &*shown),
                            ("detached", detached.to_string().as_str()),
                            ("failed", failed.join("; ").as_str()),
                        ],
                    ) {
                        eprintln!("журнал: {e}");
                    }
                    println!("{shown} больше не выдан контейнеру {selector}");
                    if detached > 0 {
                        println!("  у запущенных программ каталог отмонтирован ({detached})");
                    }
                    if failed.is_empty() {
                        0
                    } else {
                        eprintln!(
                            "  у части запущенных программ отмонтировать не удалось ({}) — \
                             завершите их или оборвите зону: vpn-zone kill",
                            failed.join("; ")
                        );
                        1
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        b"merge" => {
            let (Some(from), Some(into)) = (words.first(), words.get(1)) else {
                eprintln!("vpn-zone container merge <из контейнера> <в контейнер> [--yes]");
                return 1;
            };
            match crate::container::merge(tools, from, into, yes) {
                Ok(report) => {
                    print_merge(tools, from, into, &report);
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        _ => {
            eprintln!("vpn-zone container list|show|set|assign|unassign|grant|revoke|merge …");
            1
        }
    }
}

fn print_merge(tools: &Tools, from: &str, into: &str, report: &crate::container::MergeReport) {
    println!(
        "{from} объединён в {into}: перенесено {}, программ переназначено {}",
        report.copied, report.apps
    );
    if report.conflicts > 0 {
        println!(
            "  {} совпавших путей {into} оставил себе; версии из {from} лежат рядом:",
            report.conflicts
        );
        for dir in &report.conflicts_dirs {
            println!("    {}", dir.display());
        }
    }
    if report.skipped > 0 {
        println!(
            "  пропущено особых файлов (сокеты, каналы, пометки удаления слоя): {}",
            report.skipped
        );
    }
    if !report.new_certificates.is_empty() {
        eprintln!(
            "⚠ {into} теперь доверяет корневым сертификатам из {from} — их владельцы могут читать \
             TLS-трафик программ {into}:"
        );
        let dir = crate::container::load(tools, into).map(|c| c.trust_dir());
        for sha in &report.new_certificates {
            let subject = dir
                .as_ref()
                .and_then(|d| certificate_info(tools, &d.join(format!("{sha}.pem")), "PEM").ok())
                .map(|info| info.subject)
                .unwrap_or_default();
            eprintln!("    {} {subject}", &sha[..16.min(sha.len())]);
        }
        eprintln!("  убрать: vpn-zone trust rm {into} <начало sha256>");
    }
    let remove = match from.strip_prefix(crate::container::SANDBOX_PREFIX) {
        Some(name) => format!("vpn-zone sandbox rm {name}"),
        None => format!("vpn-zone profile rm {from}"),
    };
    println!("  {from} остался (без программ); удалить, когда проверишь результат: {remove}");
}

/// Is there a network by this name: `unconfined` (or `direct`), `offline`, or
/// a zone?
fn network_exists(tools: &Tools, name: &str) -> bool {
    name == launch::OFFLINE
        || launch::is_unconfined_name(name)
        || tools.state.join(name).join("config.conf").is_file()
}

fn source_word(source: crate::container::Source) -> &'static str {
    match source {
        crate::container::Source::Nix => "задано в Nix",
        crate::container::Source::Local => "локально",
        crate::container::Source::Default => "по умолчанию",
    }
}

fn print_container(tools: &Tools, c: &crate::container::Container) {
    let home = match c.home {
        crate::container::Home::Overlay => "слой над домом",
        crate::container::Home::Private => "свой дом",
    };
    let network = match &c.network.value {
        crate::container::Network::Ask => "спрашивать при запуске".to_owned(),
        crate::container::Network::Named(name) => name.clone(),
    };
    println!("{}", c.selector());
    println!("  дом:       {home}");
    println!("  сеть:      {network} ({})", source_word(c.network.source));
    if c.apps.is_empty() {
        println!("  программы: нет");
    } else {
        let apps: Vec<String> = c
            .apps
            .iter()
            .map(|a| format!("{} ({})", a.value, source_word(a.source)))
            .collect();
        println!("  программы: {}", apps.join(", "));
    }
    let certs = crate::trust::stored(&c.trust_dir()).len();
    if certs > 0 {
        println!(
            "  ⚠ дополнительных корневых сертификатов: {certs} (vpn-zone trust list {})",
            c.selector()
        );
    }
    if let Some(busy) = crate::container::running_network(tools, c) {
        println!("  работает:  в сети {busy}");
    }
}

fn container_list(tools: &Tools, json: bool) -> u8 {
    if json {
        println!(
            "{{\"schema_version\":{},\"containers\":{}}}",
            crate::status::SCHEMA_VERSION,
            crate::status::containers(tools)
        );
        return 0;
    }
    let all = crate::container::load_all(tools);
    if all.is_empty() {
        println!("контейнеров нет. Создать: vpn-zone profile create <имя> или vpn-zone sandbox create <имя>");
        return 0;
    }
    for c in &all {
        print_container(tools, c);
    }
    0
}

// --- SETTINGS ----------------------------------------------------------------

fn wayland_sandbox(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "on или off") else {
        return 1;
    };
    if value != "on" && value != "off" {
        eprintln!("только on или off");
        return 1;
    }
    if let Err(e) = write_setting(tools, "wayland-sandbox", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if value == "on" {
        println!(
            "программы запускаются без доступа к захвату экрана, буферу в фоне и эмуляции ввода"
        );
    } else {
        println!("ограничение снято: программы снова получают полный набор протоколов композитора");
    }
    0
}

fn isolate(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "overlay или off") else {
        return 1;
    };
    if value != "overlay" && value != "off" {
        eprintln!("только overlay или off");
        return 1;
    }
    if let Err(e) = write_setting(tools, "isolate", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if value == "overlay" {
        println!("зоны накладывают свой слой на ~/.config, ~/.local/share, ~/.cache,");
        println!("~/.mozilla, ~/.pki — программа видит настройки, но пишет в слой зоны");
    } else {
        println!("зоны используют общий профиль. Учти: браузер тогда откроет окно");
        println!("в уже запущенном процессе, и трафик пойдёт мимо VPN");
    }
    println!("поднятые зоны надо перезапустить, чтобы это применилось");
    0
}

fn mode(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "режим: picker | per-zone | both | off") else {
        return 1;
    };
    if !matches!(value.as_bytes(), b"picker" | b"per-zone" | b"both" | b"off") {
        eprintln!("неизвестный режим: {}", value.to_string_lossy());
        return 1;
    }
    if let Err(e) = write_setting(tools, "mode", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    if let Some(note) = crate::desktop::Mode::parse(&value.to_string_lossy()).deprecation() {
        eprintln!("{note}");
    }
    run_sync(tools)
}

fn default_profile(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "ask | main | own | <имя профиля>") else {
        return 1;
    };
    if !matches!(value.as_bytes(), b"ask" | b"main" | b"own")
        && !tools.profiles.join(value).is_dir()
    {
        eprintln!("профиля {} нет", value.to_string_lossy());
        return 1;
    }
    if let Err(e) = write_setting(tools, "default-profile", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("контейнер по умолчанию: {}", value.to_string_lossy());
    0
}

fn default_network(tools: &Tools, args: &[OsString]) -> u8 {
    let Some(value) = required(args, 0, "вариант: offline | unconfined | <имя зоны>")
    else {
        return 1;
    };
    // The old name is accepted and never written.
    let value = if value == launch::UNCONFINED_ALIAS {
        OsStr::new(launch::UNCONFINED)
    } else {
        value.as_os_str()
    };
    if let Err(e) = write_setting(tools, "default", value) {
        eprintln!("не записать {e}");
        return 1;
    }
    println!("по умолчанию в пикере: {}", value.to_string_lossy());
    0
}

// --- PINS --------------------------------------------------------------------

fn pins(tools: &Tools) -> u8 {
    let mut found = false;
    for (sub, network) in [(".pinned", true), (".pinnedprofile", false)] {
        for file in visible_entries(&tools.state.join(sub)) {
            if !file.is_file() {
                continue;
            }
            let key = file.file_name().unwrap_or_default();
            // The label, not the key: the key is a shortcut id
            // (com.ayugram.desktop) and tells the user nothing.
            // (`docs/GOTCHAS.md` §10)
            let label = read_setting(&tools.state.join(".labels").join(key))
                .unwrap_or_else(|| key.to_string_lossy().into_owned());
            let value = read_setting(&file).unwrap_or_default();
            if network {
                println!("{label}: сеть → {}", launch::network_name(&value));
            } else {
                let value = if value == "__main__" {
                    "основной".to_owned()
                } else {
                    value
                };
                println!("{label}: контейнер → {value}");
            }
            found = true;
        }
    }
    if !found {
        println!("закреплённых программ нет — пикер спрашивает каждый раз");
    }
    0
}

fn forget(tools: &Tools, args: &[OsString]) -> u8 {
    const SUBDIRS: [&str; 4] = [".pinned", ".last", ".lastprofile", ".pinnedprofile"];
    let Some(what) = required(args, 0, "имя программы или --all") else {
        return 1;
    };
    if what == "--all" {
        for sub in SUBDIRS {
            let _ = crate::sys::remove_tree(&tools.state.join(sub));
        }
        println!("сброшено для всех программ");
    } else {
        for sub in SUBDIRS {
            let _ = fs::remove_file(tools.state.join(sub).join(what));
        }
        println!("сброшено для {}", what.to_string_lossy());
    }
    0
}

// --- SHORTCUTS ---------------------------------------------------------------

/// The four arguments the `.desktop` generator takes. The runner and the picker
/// are PROFILE paths, not store ones: that is what breaks the dependency cycle
/// (`vpn-zone` calls sync, sync writes `vpn-zone` into the shortcuts) and keeps
/// the shortcuts from going stale after every rebuild. (`docs/GOTCHAS.md` §10)
fn sync_argv(tools: &Tools) -> Vec<OsString> {
    vec![
        tools.core.clone().into(),
        "sync".into(),
        tools.state.clone().into(),
        tools.home.clone().into(),
        tools.runner.clone().into(),
        tools.picker.clone().into(),
        tools.systemctl.clone().into(),
    ]
}

/// `vpn-zone sync` — become the generator, as the shell version's `exec` did.
fn exec_sync(tools: &Tools) -> u8 {
    let argv = sync_argv(tools);
    let e = exec_command(&argv);
    eprintln!("не удалось запустить {}: {e}", tools.core.display());
    EXIT_NOT_STARTED
}

/// The same, as a child: `mode` and `rm` have something to say afterwards.
fn run_sync(tools: &Tools) -> u8 {
    let argv = sync_argv(tools);
    match Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .status()
    {
        Ok(status) => status.code().map_or(1, |c| c as u8),
        Err(e) => {
            eprintln!("не запустить {}: {e}", tools.core.display());
            EXIT_NOT_STARTED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `zone.pid` outlives a stopped zone; with the holder's start time beside
    /// it, a number that went to another process is not the zone.
    #[test]
    fn a_zone_is_up_only_while_its_own_holder_lives() {
        let state = std::env::temp_dir().join(format!("vz-zone-pid-{}", std::process::id()));
        let dir = state.join("nl");
        fs::create_dir_all(&dir).unwrap();
        let me = std::process::id() as i32;
        fs::write(dir.join("zone.pid"), format!("{me}\n")).unwrap();
        // A holder from before the start time was noted: by its number.
        assert_eq!(zone_pid(&state, OsStr::new("nl")), Some(me));
        let start = crate::sys::start_time(me).unwrap();
        fs::write(dir.join("zone.start"), format!("{start}\n")).unwrap();
        assert_eq!(zone_pid(&state, OsStr::new("nl")), Some(me));
        fs::write(dir.join("zone.start"), "1\n").unwrap();
        assert_eq!(zone_pid(&state, OsStr::new("nl")), None);
        let _ = fs::remove_dir_all(&state);
    }

    #[test]
    fn carriage_returns_go_only_from_the_ends_of_lines() {
        assert_eq!(strip_cr(b"a\r\nb\r\n"), b"a\nb\n".to_vec());
        // Only ONE, and only at the end — a `\r` in the middle of a value is
        // somebody's data, not a line ending.
        assert_eq!(strip_cr(b"a\r\r\n"), b"a\r\n".to_vec());
        assert_eq!(strip_cr(b"a\rb\n"), b"a\rb\n".to_vec());
        // A file without a trailing newline keeps not having one.
        assert_eq!(strip_cr(b"a\r\nb"), b"a\nb".to_vec());
        assert_eq!(strip_cr(b""), b"".to_vec());
    }

    #[test]
    fn liveness_is_a_handshake_or_the_word_connected() {
        // A WireGuard zone, unchanged.
        let wg = "interface: awg0\n\npeer: p\n  latest handshake: now\n";
        assert_eq!(liveness_line(wg).as_deref(), Some("latest handshake: now"));

        // An OpenConnect one, whose mirror has no handshake in it at all.
        let oc =
            "interface: awg0\n  backend: openconnect\n  connected: yes\n  address: 10.5.0.7/32\n";
        assert_eq!(liveness_line(oc).as_deref(), Some("connected: yes"));

        // And the two dead shapes.
        let gone = "interface: awg0\n  backend: openconnect\n  disconnected: the tunnel interface is gone\n";
        assert_eq!(liveness_line(gone), None);
        assert_eq!(liveness_line("interface: awg0\n\npeer: p\n"), None);
        assert_eq!(liveness_line(""), None);
    }

    #[test]
    fn a_handshake_is_looked_for_inside_a_peer_block() {
        let mirror = "\
interface: awg0
  public key: k
  listening port: 51820

peer: p
  endpoint: 10.0.0.1:51820
  latest handshake: 1 minute, 5 seconds ago
  transfer: 1 KiB received
";
        assert_eq!(
            handshake_line(mirror).as_deref(),
            Some("latest handshake: 1 minute, 5 seconds ago")
        );
        // A peer that has never answered has no such line at all.
        assert_eq!(
            handshake_line("interface: awg0\n\npeer: p\n  transfer: 0 B\n"),
            None
        );
        assert_eq!(handshake_line(""), None);
        // Case-insensitive, as `grep -i` was.
        assert!(handshake_line("peer: p\n  Latest Handshake: now\n").is_some());
        // Too far from any peer line: the twenty-line window of `grep -A20`.
        let far = format!("peer: p\n{}  latest handshake: now\n", "  x\n".repeat(25));
        assert_eq!(handshake_line(&far), None);
    }

    #[test]
    fn a_stray_pasta_is_recognised_by_the_namespace_in_its_command_line() {
        assert_eq!(
            netns_pid(b"pasta\0--netns\0/proc/12345/ns/net\0-I\0hostif\0"),
            Some(12345)
        );
        // The first one wins, as `head -1` did.
        assert_eq!(netns_pid(b"pasta /proc/7/ns/net /proc/9/ns/net"), Some(7));
        for junk in [
            &b"pasta"[..],
            b"pasta --netns /proc//ns/net",
            b"pasta /proc/12/ns/mnt",
            b"pasta /proc/12x/ns/net",
            b"",
        ] {
            assert!(netns_pid(junk).is_none(), "{junk:?} приняли за netns");
        }
    }

    #[test]
    fn names_that_would_break_a_dialog_or_a_path_are_refused() {
        for good in ["work", "личное", "a.b", "a_b", "a-b"] {
            assert!(safe_name(OsStr::new(good)), "«{good}» должно быть можно");
        }
        for bad in ["", "a/b", "a b", "-a", ".a", "/"] {
            assert!(!safe_name(OsStr::new(bad)), "«{bad}» должно быть нельзя");
        }
        // Zone names end up in unit names: stricter still.
        for good in ["nl", "nl-2", "a_b"] {
            assert!(safe_zone_name(OsStr::new(good)));
        }
        for bad in ["", "nl 2", "nl.2", "личное", "nl/2"] {
            assert!(
                !safe_zone_name(OsStr::new(bad)),
                "«{bad}» должно быть нельзя"
            );
        }
    }

    #[test]
    fn sizes_read_like_du() {
        assert_eq!(human_size(0), "0");
        assert_eq!(human_size(512), "512");
        assert_eq!(human_size(4096), "4.0K");
        assert_eq!(human_size(1536), "1.5K");
        // Rounded up, never down: a byte over is a tenth more.
        assert_eq!(human_size(1024 * 1024 + 1), "1.1M");
        assert_eq!(human_size(10 * 1024), "10K");
        assert_eq!(human_size(11 * 1024 + 1), "12K");
        assert_eq!(human_size(1024 * 1024), "1.0M");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0G");
    }

    #[test]
    fn the_help_text_lists_every_verb_the_dispatcher_knows() {
        for verb in [
            "add",
            "up",
            "down",
            "list",
            "status",
            "run",
            "rm",
            "sync",
            "mode",
            "default",
            "gc",
            "perms",
            "sandbox",
            "default-profile",
            "pins",
            "forget",
            "isolate",
            "reset-profile",
            "wayland-sandbox",
            "check",
            "lock",
            "trust",
            "container",
        ] {
            assert!(
                USAGE.contains(&format!("vpn-zone {verb}")),
                "в справке нет «{verb}»"
            );
        }
    }
}
