//! `cellward-oc-auth` — the OpenConnect login, as its gateway asks it
//! (`docs/PERMISSIONS.md` §11.17; what it says and hears is
//! `vpn_zone::oc_form`).
//!
//! The one binary linked with libopenconnect: the library, and what it pulls
//! in, stays out of every other process of cellward. It reads one request on
//! its standard input, goes to the gateway, and says every form the gateway
//! asks on its standard output — one JSON object a line — reading the
//! answer to each from its standard input. What comes out is the session's
//! cookie, never kept anywhere: the one who ran this hands it to the client
//! (`--cookie-on-stdin`). A look (`probe`) sends nothing and ends at the
//! first form: the server answered as its protocol, with this certificate.
//!
//! Where it goes is pinned twice over: the name is resolved once, here, and
//! the login goes to that address and no other — a redirect to another host
//! is refused, since the zone's filter lets its client reach that one
//! address alone —; and with a pin the certificate must be the pinned one,
//! whoever signed it (the system's authorities are then not asked).

#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::io::{self, BufRead, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::process::ExitCode;

use vpn_zone::oc_form::{self, Answer, Choice, Field, Form, Kind, Request, Said};

// --- libopenconnect, as its `openconnect.h` (API 5.x) has it --------------

#[repr(C)]
struct VpnInfo {
    _private: [u8; 0],
}

// The C layouts, whole: some fields are there for the layout only.
#[allow(dead_code)]
#[repr(C)]
struct FormOpt {
    next: *mut FormOpt,
    kind: c_int,
    name: *mut c_char,
    label: *mut c_char,
    value: *mut c_char,
    flags: c_uint,
    reserved: *mut c_void,
}

/// The public head of `struct oc_choice`; the library's private fields
/// follow, and are never touched.
#[allow(dead_code)]
#[repr(C)]
struct OcChoice {
    name: *mut c_char,
    label: *mut c_char,
    auth_type: *mut c_char,
    override_name: *mut c_char,
    override_label: *mut c_char,
}

#[repr(C)]
struct FormOptSelect {
    form: FormOpt,
    nr_choices: c_int,
    choices: *mut *mut OcChoice,
}

#[allow(dead_code)]
#[repr(C)]
struct AuthForm {
    banner: *mut c_char,
    message: *mut c_char,
    error: *mut c_char,
    auth_id: *mut c_char,
    method: *mut c_char,
    action: *mut c_char,
    opts: *mut FormOpt,
    authgroup_opt: *mut FormOptSelect,
    authgroup_selection: c_int,
}

const OPT_TEXT: c_int = 1;
const OPT_PASSWORD: c_int = 2;
const OPT_SELECT: c_int = 3;
const OPT_HIDDEN: c_int = 4;
const OPT_TOKEN: c_int = 5;
const OPT_IGNORE: c_uint = 0x0001;

const RESULT_OK: c_int = 0;
const RESULT_CANCELLED: c_int = 1;
const RESULT_NEWGROUP: c_int = 2;

const PRG_ERR: c_int = 0;
const PRG_INFO: c_int = 1;

/// What the command-line client calls itself, unless `--useragent` says
/// otherwise: a gateway that knows the one knows the other.
const USERAGENT: &CStr = c"Open AnyConnect VPN Agent";

type ValidateFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int;
type WriteConfigFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type FormFn = unsafe extern "C" fn(*mut c_void, *mut AuthForm) -> c_int;
type ProgressFn = unsafe extern "C" fn(*mut c_void, c_int, *const c_char, ...);
/// A setter of the handle's that takes a string.
type SetFn = unsafe extern "C" fn(*mut VpnInfo, *const c_char) -> c_int;
type GaiFn = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;

extern "C" {
    fn openconnect_init_ssl() -> c_int;
    fn openconnect_vpninfo_new(
        useragent: *const c_char,
        validate: Option<ValidateFn>,
        write_config: Option<WriteConfigFn>,
        form: Option<FormFn>,
        progress: Option<ProgressFn>,
        privdata: *mut c_void,
    ) -> *mut VpnInfo;
    fn openconnect_vpninfo_free(vpninfo: *mut VpnInfo);
    fn openconnect_set_protocol(vpninfo: *mut VpnInfo, protocol: *const c_char) -> c_int;
    fn openconnect_parse_url(vpninfo: *mut VpnInfo, url: *const c_char) -> c_int;
    fn openconnect_set_urlpath(vpninfo: *mut VpnInfo, path: *const c_char) -> c_int;
    fn openconnect_set_sni(vpninfo: *mut VpnInfo, sni: *const c_char) -> c_int;
    fn openconnect_set_useragent(vpninfo: *mut VpnInfo, useragent: *const c_char) -> c_int;
    fn openconnect_set_version_string(vpninfo: *mut VpnInfo, version: *const c_char) -> c_int;
    fn openconnect_set_reported_os(vpninfo: *mut VpnInfo, os: *const c_char) -> c_int;
    fn openconnect_set_localname(vpninfo: *mut VpnInfo, name: *const c_char) -> c_int;
    fn openconnect_set_xmlpost(vpninfo: *mut VpnInfo, enable: c_int);
    fn openconnect_set_system_trust(vpninfo: *mut VpnInfo, val: c_uint);
    fn openconnect_set_loglevel(vpninfo: *mut VpnInfo, level: c_int);
    fn openconnect_override_getaddrinfo(vpninfo: *mut VpnInfo, gai: Option<GaiFn>);
    fn openconnect_obtain_cookie(vpninfo: *mut VpnInfo) -> c_int;
    fn openconnect_get_cookie(vpninfo: *mut VpnInfo) -> *const c_char;
    fn openconnect_get_connect_url(vpninfo: *mut VpnInfo) -> *const c_char;
    fn openconnect_get_peer_cert_hash(vpninfo: *mut VpnInfo) -> *const c_char;
    fn openconnect_check_peer_cert_hash(vpninfo: *mut VpnInfo, hash: *const c_char) -> c_int;
    fn openconnect_set_option_value(opt: *mut FormOpt, value: *const c_char) -> c_int;
    /// `oc_auth_shim.c`: formats the line and hands it to
    /// [`cellward_oc_progress`].
    fn cellward_oc_progress_shim(privdata: *mut c_void, level: c_int, fmt: *const c_char, ...);
}

// --- ONE LOGIN ---------------------------------------------------------------

/// What the callbacks share: the library hands this back as its `privdata`.
struct Ctx {
    vpninfo: *mut VpnInfo,
    probe: bool,
    pin: Option<CString>,
    /// The gateway's name, as the library asks for it, and the one address
    /// it goes to instead.
    host: CString,
    address: CString,
    /// A look's finding: the certificate, and the first form.
    probed: RefCell<Option<(String, Form)>>,
    /// The last error the library said, for the person.
    last_error: RefCell<String>,
    /// Said on our side: why the library stopped.
    why: RefCell<Option<String>>,
}

/// One line out, at once: the one who runs this waits on it.
fn say(said: &Said) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", said.encode());
    let _ = out.flush();
}

/// A C string of the library's as text; null as empty.
///
/// # Safety
/// `text` is null or a valid NUL-terminated string.
unsafe fn text_of(text: *const c_char) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: non-null, and NUL-terminated per the caller.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}

/// Formatted by the shim; one line to the one who runs this. An error is
/// kept, for the person.
///
/// # Safety
/// `privdata` is the [`Ctx`] of this login; `text` a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn cellward_oc_progress(
    privdata: *mut c_void,
    level: c_int,
    text: *const c_char,
) {
    // SAFETY: the library hands back the pointer given to it — a live Ctx.
    let ctx = unsafe { &*(privdata as *const Ctx) };
    // SAFETY: the shim's own buffer, NUL-terminated by vsnprintf.
    let text = oc_form::bounded(unsafe { &text_of(text) }, oc_form::MAX_TEXT, false);
    let text = text.trim().to_owned();
    if text.is_empty() {
        return;
    }
    if level <= PRG_ERR {
        *ctx.last_error.borrow_mut() = text.clone();
    }
    say(&Said::Log { text });
}

/// The server's certificate, when the system's authorities do not vouch
/// for it — or, with a pin, always: it must be the pinned one. A look takes
/// any: it sends nothing, and the certificate is what it shows.
unsafe extern "C" fn validate(privdata: *mut c_void, reason: *const c_char) -> c_int {
    // SAFETY: our Ctx, handed back.
    let ctx = unsafe { &*(privdata as *const Ctx) };
    if ctx.probe {
        return 0;
    }
    match &ctx.pin {
        // SAFETY: the library's own handle, and a C string of ours.
        Some(pin)
            if unsafe { openconnect_check_peer_cert_hash(ctx.vpninfo, pin.as_ptr()) } == 0 =>
        {
            0
        }
        Some(_) => {
            *ctx.why.borrow_mut() = Some(
                "сертификат шлюза не тот, что закреплён: либо шлюз сменил сертификат, либо это \
                 не тот сервер — вход не начат"
                    .to_owned(),
            );
            1
        }
        None => {
            // SAFETY: the library's reason, a C string or null.
            let reason = unsafe { text_of(reason) };
            *ctx.why.borrow_mut() = Some(format!(
                "сертификату шлюза система не доверяет ({reason}) — закрепите его отпечаток \
                 (ServerCert)"
            ));
            1
        }
    }
}

/// Only the gateway, and only at its one address.
unsafe extern "C" fn resolve(
    privdata: *mut c_void,
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    // SAFETY: our Ctx, handed back.
    let ctx = unsafe { &*(privdata as *const Ctx) };
    // SAFETY: the library's node name, a C string or null.
    if node.is_null() || unsafe { CStr::from_ptr(node) } != ctx.host.as_c_str() {
        *ctx.why.borrow_mut() = Some(format!(
            "шлюз отправляет на другой хост ({}) — вход только к самому шлюзу",
            // SAFETY: as above.
            unsafe { text_of(node) }
        ));
        return libc::EAI_NONAME;
    }
    // SAFETY: an address literal of ours, and the library's own arguments.
    unsafe { libc::getaddrinfo(ctx.address.as_ptr(), service, hints, res) }
}

/// A form of the library's as data, and the options of the fields it
/// shows, in order; `Err` for one that cannot be answered here (a
/// browser's sign-on).
///
/// # Safety
/// `form` is a live form of the library's.
unsafe fn read_form(form: &AuthForm) -> Result<(Form, Vec<*mut FormOpt>), String> {
    let mut shown = Form {
        // SAFETY: the form's strings, owned by the library while it lives.
        banner: oc_form::bounded(unsafe { &text_of(form.banner) }, oc_form::MAX_TEXT, true),
        message: oc_form::bounded(unsafe { &text_of(form.message) }, oc_form::MAX_TEXT, true),
        error: oc_form::bounded(unsafe { &text_of(form.error) }, oc_form::MAX_TEXT, true),
        ..Form::default()
    };
    let mut opts = Vec::new();
    let mut at = form.opts;
    while !at.is_null() && shown.fields.len() < oc_form::MAX_ITEMS {
        // The library's own pointer is what an answer is written through,
        // not one made from the reference read here.
        let raw = at;
        // SAFETY: a node of the library's list, live while the form is.
        let opt = unsafe { &*raw };
        at = opt.next;
        if opt.flags & OPT_IGNORE != 0 || opt.kind == OPT_HIDDEN {
            continue;
        }
        let kind = match opt.kind {
            OPT_TEXT => Kind::Text,
            OPT_PASSWORD => Kind::Password,
            OPT_SELECT => Kind::Select,
            OPT_TOKEN => Kind::Token,
            _ => {
                return Err(
                    "шлюз просит вход через браузер (единый вход, SSO) — такого входа \
                            здесь пока нет"
                        .to_owned(),
                )
            }
        };
        // SAFETY: the option's strings, owned by the library.
        let name = oc_form::bounded(unsafe { &text_of(opt.name) }, oc_form::MAX_LABEL, false);
        let label = oc_form::bounded(unsafe { &text_of(opt.label) }, oc_form::MAX_LABEL, false);
        let mut choices = Vec::new();
        let mut value = String::new();
        if kind == Kind::Select {
            // SAFETY: a select option IS a `struct oc_form_opt_select`,
            // its head the option itself.
            let select = unsafe { &*(opt as *const FormOpt as *const FormOptSelect) };
            let count = usize::try_from(select.nr_choices).unwrap_or(0);
            for i in 0..count.min(oc_form::MAX_ITEMS) {
                // SAFETY: `nr_choices` entries, each a live choice.
                let choice = unsafe { &**select.choices.add(i) };
                choices.push(Choice {
                    // SAFETY: the choice's strings, owned by the library.
                    name: oc_form::bounded(
                        unsafe { &text_of(choice.name) },
                        oc_form::MAX_LABEL,
                        false,
                    ),
                    label: oc_form::bounded(
                        unsafe { &text_of(choice.label) },
                        oc_form::MAX_LABEL,
                        false,
                    ),
                });
            }
            // SAFETY: the option's value, the chosen name or null.
            value = oc_form::bounded(unsafe { &text_of(opt.value) }, oc_form::MAX_LABEL, false);
        }
        if std::ptr::eq(at_select(form), opt) {
            shown.group = Some(name.clone());
        }
        shown.fields.push(Field {
            name,
            label,
            kind,
            value,
            choices,
        });
        opts.push(raw);
    }
    Ok((shown, opts))
}

/// The form's group field, as an option.
fn at_select(form: &AuthForm) -> *const FormOpt {
    form.authgroup_opt as *const FormOpt
}

/// The answer to a form, from our standard input.
fn read_answer() -> Answer {
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => Answer::Cancel,
        Ok(_) => Answer::decode(line.trim()).unwrap_or(Answer::Cancel),
    }
}

/// A form of the gateway's: a look keeps it and stops; a login says it,
/// and fills it with the answer — the group first, whose new choice is a
/// new form.
unsafe extern "C" fn process_form(privdata: *mut c_void, form: *mut AuthForm) -> c_int {
    // SAFETY: our Ctx, handed back; the library's live form.
    let (ctx, form) = unsafe { (&*(privdata as *const Ctx), &*form) };
    // SAFETY: a live form.
    let (shown, opts) = match unsafe { read_form(form) } {
        Ok(read) => read,
        Err(why) => {
            *ctx.why.borrow_mut() = Some(why);
            return RESULT_CANCELLED;
        }
    };
    if ctx.probe {
        // SAFETY: the library's handle; the string lives while it does.
        let fingerprint = unsafe { text_of(openconnect_get_peer_cert_hash(ctx.vpninfo)) };
        *ctx.probed.borrow_mut() = Some((fingerprint, shown));
        return RESULT_CANCELLED;
    }
    say(&Said::Form(shown.clone()));
    let Answer::Values(values) = read_answer() else {
        *ctx.why.borrow_mut() = Some("вход отменён".to_owned());
        return RESULT_CANCELLED;
    };
    let set = |opt: *mut FormOpt, value: &str| -> bool {
        let Ok(value) = CString::new(value) else {
            return false;
        };
        // SAFETY: a live option of this form; the library copies the value.
        unsafe { openconnect_set_option_value(opt, value.as_ptr()) == 0 }
    };
    if let Some(group) = &shown.group {
        let current = shown
            .fields
            .iter()
            .find(|f| &f.name == group)
            .map(|f| f.value.as_str());
        if let Some(chosen) = values.get(group) {
            if Some(chosen.as_str()) != current {
                if !set(form.authgroup_opt as *mut FormOpt, chosen) {
                    *ctx.why.borrow_mut() = Some(format!("у шлюза нет группы «{chosen}»"));
                    return RESULT_CANCELLED;
                }
                return RESULT_NEWGROUP;
            }
        }
    }
    for (field, opt) in shown.fields.iter().zip(opts) {
        if let Some(value) = values.get(&field.name) {
            if !set(opt, value) {
                *ctx.why.borrow_mut() = Some(format!("поле «{}»: не тот ответ", field.label));
                return RESULT_CANCELLED;
            }
        }
    }
    RESULT_OK
}

/// The one address the gateway's name has for this login: IPv4 first, as
/// the zone's holder picks it (`zone::prepare_openconnect`), so that the
/// client goes where the login went.
fn address_of(server: &str, port: u16) -> Result<IpAddr, String> {
    if let Ok(literal) = server.parse::<IpAddr>() {
        return Ok(literal);
    }
    let addrs: Vec<IpAddr> = (server, port)
        .to_socket_addrs()
        .map_err(|e| format!("имя шлюза {server} не находится ({e})"))?
        .map(|a| a.ip())
        .collect();
    addrs
        .iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .ok_or_else(|| format!("у шлюза {server} нет адреса IPv4"))
}

fn c_string(text: &str, what: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| format!("{what}: нулевой байт"))
}

fn run(req: &Request) -> Result<Said, String> {
    let port = req.port.unwrap_or(443);
    let address = address_of(&req.server, port)?;
    let host = c_string(&req.server, "сервер")?;
    let url = if req.server.contains(':') {
        format!("https://[{}]:{port}/", req.server)
    } else {
        format!("https://{}:{port}/", req.server)
    };
    let ctx = Box::new(Ctx {
        vpninfo: std::ptr::null_mut(),
        probe: req.probe,
        pin: req.pin.as_deref().map(|p| c_string(p, "пин")).transpose()?,
        host,
        address: c_string(&address.to_string(), "адрес")?,
        probed: RefCell::new(None),
        last_error: RefCell::new(String::new()),
        why: RefCell::new(None),
    });
    let ctx = Box::into_raw(ctx);
    // SAFETY: the library's own calls on its own handle, with C strings of
    // ours that outlive them, and callbacks that take `ctx` back — live
    // until it is freed below, after the handle.
    let result = unsafe {
        openconnect_init_ssl();
        let vpninfo = openconnect_vpninfo_new(
            USERAGENT.as_ptr(),
            Some(validate),
            None,
            Some(process_form),
            Some(cellward_oc_progress_shim),
            ctx as *mut c_void,
        );
        if vpninfo.is_null() {
            drop(Box::from_raw(ctx));
            return Err("libopenconnect не создала подключение".to_owned());
        }
        (*ctx).vpninfo = vpninfo;
        let outcome = login(vpninfo, &*ctx, req, &url, address);
        openconnect_vpninfo_free(vpninfo);
        outcome
    };
    // SAFETY: made above, and nothing holds it any more.
    drop(unsafe { Box::from_raw(ctx) });
    result
}

/// The login itself, on a live handle.
///
/// # Safety
/// `vpninfo` is live, and `ctx` is its callbacks' `privdata`.
unsafe fn login(
    vpninfo: *mut VpnInfo,
    ctx: &Ctx,
    req: &Request,
    url: &str,
    address: IpAddr,
) -> Result<Said, String> {
    let set = |what: &str, value: &Option<String>, f: SetFn| {
        let Some(value) = value else {
            return Ok(());
        };
        let value = c_string(value, what)?;
        // SAFETY: a live handle and a C string that outlives the call.
        if unsafe { f(vpninfo, value.as_ptr()) } != 0 {
            return Err(format!("{what}: {value:?} не принят"));
        }
        Ok(())
    };
    set(
        "протокол",
        &Some(req.protocol.clone()),
        openconnect_set_protocol,
    )?;
    set("адрес шлюза", &Some(url.to_owned()), openconnect_parse_url)?;
    set("--usergroup", &req.usergroup, openconnect_set_urlpath)?;
    set("--sni", &req.sni, openconnect_set_sni)?;
    set("--useragent", &req.useragent, openconnect_set_useragent)?;
    set(
        "--version-string",
        &req.version_string,
        openconnect_set_version_string,
    )?;
    set("--os", &req.os, openconnect_set_reported_os)?;
    set(
        "--local-hostname",
        &req.local_hostname,
        openconnect_set_localname,
    )?;
    // SAFETY: a live handle, and callbacks that take `ctx` back.
    unsafe {
        if req.no_xmlpost {
            openconnect_set_xmlpost(vpninfo, 0);
        }
        // A pin is the whole of the trust: every certificate goes through
        // `validate`, however well signed.
        if ctx.pin.is_some() && !req.probe {
            openconnect_set_system_trust(vpninfo, 0);
        }
        openconnect_set_loglevel(vpninfo, PRG_INFO);
        openconnect_override_getaddrinfo(vpninfo, Some(resolve));
    }
    // SAFETY: a live handle.
    let code = unsafe { openconnect_obtain_cookie(vpninfo) };
    let why = || {
        ctx.why.borrow().clone().unwrap_or_else(|| {
            let last = ctx.last_error.borrow();
            if last.is_empty() {
                format!("шлюз не ответил как {} (код {code})", req.protocol)
            } else {
                last.clone()
            }
        })
    };
    // SAFETY: a live handle; the strings live while it does, and are copied.
    let fingerprint = || unsafe { text_of(openconnect_get_peer_cert_hash(vpninfo)) };
    if req.probe {
        if let Some((fingerprint, form)) = ctx.probed.borrow_mut().take() {
            return Ok(Said::Probe {
                fingerprint,
                form: Some(form),
            });
        }
        return match code {
            // In with no form at all (a certificate's login): it answered.
            0 => Ok(Said::Probe {
                fingerprint: fingerprint(),
                form: None,
            }),
            _ => Err(why()),
        };
    }
    if code != 0 {
        return Err(why());
    }
    // SAFETY: a live handle.
    let (cookie, connect_url) = unsafe {
        (
            text_of(openconnect_get_cookie(vpninfo)),
            text_of(openconnect_get_connect_url(vpninfo)),
        )
    };
    if cookie.is_empty() {
        return Err("шлюз впустил, но не дал сессии".to_owned());
    }
    Ok(Said::Done {
        cookie,
        connect_url,
        fingerprint: fingerprint(),
        address: address.to_string(),
    })
}

fn main() -> ExitCode {
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        say(&Said::Failed {
            why: "нет запроса на входе".to_owned(),
        });
        return ExitCode::from(2);
    }
    let req = match Request::decode(line.trim()) {
        Ok(req) => req,
        Err(e) => {
            say(&Said::Failed {
                why: format!("запрос не прочитан: {e}"),
            });
            return ExitCode::from(2);
        }
    };
    match run(&req) {
        Ok(said) => {
            say(&said);
            ExitCode::SUCCESS
        }
        Err(why) => {
            say(&Said::Failed { why });
            ExitCode::from(1)
        }
    }
}
