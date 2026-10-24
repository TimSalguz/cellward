//! The clipboard history's daemon, as the history window asks it: its
//! socket of questions, `$XDG_RUNTIME_DIR/cellward-clip.sock` (made and
//! answered by `cellward-clip daemon` — `clip/src/protocol.rs` of cellward
//! is the contract, repeated here: this crate does not depend on the clip
//! crate, whose key and store the window must never hold).
//!
//! One request line, its answer, the connection closed. Values are
//! percent-encoded — `%`, tab, line feed and `=` as `%25`, `%09`, `%0A`,
//! `%3D` —, anything else as UTF-8; whatever comes back is decoded, every
//! `%xx` (the daemon writes a type's `,` as `%2C`). A failure is one line,
//! `error⇥<why>`, in Russian, shown as it is.
//!
//! Nothing here touches the clipboard: the window reads entries, their
//! contents, and asks a copy moved or deleted. Pasting is the caller's
//! (`cellward clip-window`): the window prints which entry and exits.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A search's page: what the window asks at a time.
pub const PAGE: usize = 50;

/// The daemon's socket.
pub fn socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("cellward-clip.sock")
}

/// `%`, tab, line feed and `=` written as `%xx`.
pub fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\t' => out.push_str("%09"),
            '\n' => out.push_str("%0A"),
            '=' => out.push_str("%3D"),
            c => out.push(c),
        }
    }
    out
}

/// Every `%xx` read back; `None` for one that is not two hex digits, or
/// bytes that are not UTF-8.
pub fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// One entry of a history, as a search answers it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    /// When it was first copied, and last, in ms since the epoch.
    pub copied_at: i64,
    pub last_copied: i64,
    pub copies: u32,
    pub pastes: u32,
    /// 0: never pasted.
    pub last_pasted: i64,
    /// `(type, size in bytes)`, as it was offered.
    pub types: Vec<(String, u64)>,
    /// The start of its text (the daemon's cut), or a word for what it is.
    pub preview: String,
}

impl Entry {
    /// Its image type, when it is an image.
    pub fn image(&self) -> Option<&(String, u64)> {
        self.types.iter().find(|(t, _)| t.starts_with("image/"))
    }

    /// The size of its plain text, when it has one: more than the
    /// preview's says the preview is cut.
    pub fn text_size(&self) -> Option<u64> {
        self.types
            .iter()
            .find(|(t, _)| {
                t == "text/plain;charset=utf-8" || t == "text/plain" || t == "UTF8_STRING"
            })
            .or_else(|| self.types.iter().find(|(t, _)| t.starts_with("text/plain")))
            .map(|(_, s)| *s)
    }

    /// The text type to ask `get` for the whole text.
    pub fn text_type(&self) -> Option<&str> {
        ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"]
            .into_iter()
            .find(|want| self.types.iter().any(|(t, _)| t == want))
            .or_else(|| {
                self.types
                    .iter()
                    .map(|(t, _)| t.as_str())
                    .find(|t| t.starts_with("text/"))
            })
    }
}

fn parse_entry(line: &str) -> Option<Entry> {
    let f: Vec<&str> = line.splitn(8, '\t').collect();
    let [id, copied_at, last_copied, copies, pastes, last_pasted, types, preview] = f.as_slice()
    else {
        return None;
    };
    let types = types
        .split(',')
        .filter(|t| !t.is_empty())
        .filter_map(|t| {
            let (mime, size) = t.rsplit_once(':')?;
            Some((decode(mime)?, size.parse().ok()?))
        })
        .collect();
    Some(Entry {
        id: id.parse().ok()?,
        copied_at: copied_at.parse().ok()?,
        last_copied: last_copied.parse().ok()?,
        copies: copies.parse().ok()?,
        pastes: pastes.parse().ok()?,
        last_pasted: last_pasted.parse().ok()?,
        types,
        preview: decode(preview).unwrap_or_else(|| (*preview).to_owned()),
    })
}

/// The `error⇥<why>` of an answer, when it is one.
fn refusal(answer: &str) -> Option<String> {
    answer
        .strip_prefix("error\t")
        .map(|why| decode(why.trim_end()).unwrap_or_else(|| why.trim_end().to_owned()))
}

/// A search's answer: its entries, newest first, as they came; a line that
/// does not read is skipped (a later daemon's field more is not an error).
pub fn parse_entries(answer: &str) -> Result<Vec<Entry>, String> {
    if let Some(why) = refusal(answer) {
        return Err(why);
    }
    Ok(answer.lines().filter_map(parse_entry).collect())
}

/// `histories`' answer: a name a line.
pub fn parse_histories(answer: &str) -> Result<Vec<String>, String> {
    if let Some(why) = refusal(answer) {
        return Err(why);
    }
    Ok(answer
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| decode(l).unwrap_or_else(|| l.to_owned()))
        .collect())
}

/// `ok` or `ok⇥<value>`: the value (empty for a plain `ok`).
pub fn parse_ok(answer: &str) -> Result<String, String> {
    if let Some(why) = refusal(answer) {
        return Err(why);
    }
    let line = answer.lines().next().unwrap_or("");
    match line.split_once('\t') {
        Some(("ok", value)) => Ok(value.to_owned()),
        None if line == "ok" => Ok(String::new()),
        _ => Err(format!("служба истории ответила непонятно: «{line}»")),
    }
}

/// What a search asks besides its history: each condition optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Words, every one to occur (any case).
    pub words: String,
    /// A pattern (the builder's, or typed).
    pub re: Option<String>,
    /// Types: `text/plain`, `image/*`, `text/uri-list`.
    pub types: Vec<String>,
    /// Copied, pasted within `[from, to)`, in ms.
    pub copied: Option<(i64, i64)>,
    pub pasted: Option<(i64, i64)>,
    /// Copied around a moment: `(at, window)` in ms.
    pub around: Option<(i64, i64)>,
}

/// `search⇥<history>⇥<key=value>…`: the filter's conditions, a page of
/// `limit` older than `before`.
pub fn search_request(history: &str, filter: &Filter, before: Option<u64>, limit: usize) -> String {
    let mut words = vec!["search".to_owned(), encode(history)];
    if !filter.words.trim().is_empty() {
        words.push(format!("q={}", encode(filter.words.trim())));
    }
    if let Some(re) = filter.re.as_deref().filter(|r| !r.is_empty()) {
        words.push(format!("re={}", encode(re)));
    }
    for t in &filter.types {
        words.push(format!("type={}", encode(t)));
    }
    if let Some((from, to)) = filter.copied {
        words.push(format!("copied={from}-{to}"));
    }
    if let Some((from, to)) = filter.pasted {
        words.push(format!("pasted={from}-{to}"));
    }
    if let Some((at, window)) = filter.around {
        words.push(format!("around={at}:{window}"));
    }
    if let Some(id) = before {
        words.push(format!("before={id}"));
    }
    words.push(format!("limit={}", limit.min(200)));
    words.join("\t")
}

pub fn get_request(history: &str, id: u64, mime: &str) -> String {
    format!("get\t{}\t{id}\t{}", encode(history), encode(mime))
}

pub fn move_request(from: &str, id: u64, to: &str) -> String {
    format!("move\t{}\t{id}\t{}", encode(from), encode(to))
}

pub fn delete_request(history: &str, id: u64) -> String {
    format!("delete\t{}\t{id}", encode(history))
}

/// Save a copy in this history's encrypted favourites, leaving the original.
pub fn favorite_request(history: &str, id: u64) -> String {
    format!("favorite\t{}\t{id}", encode(history))
}

/// Move a text entry into the same buffer's separately encrypted password shelf.
pub fn secret_request(history: &str, id: u64, label: &str) -> String {
    format!("secret\t{}\t{id}\t{}", encode(history), encode(label))
}

pub fn select_request(history: &str, id: u64) -> String {
    format!("select\t{}\t{id}", encode(history))
}

/// Why an answer did not come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Nobody listens: the history is not turned on.
    Off,
    /// The daemon refused, or the connection broke: what to show.
    Said(String),
}

impl Failure {
    pub fn text(&self) -> String {
        match self {
            Failure::Off => {
                "История буфера выключена: programs.cellward.clipboard.history".to_owned()
            }
            Failure::Said(why) => why.clone(),
        }
    }
}

/// The longest answer read: a whole image, with room — more is a daemon
/// gone wrong, not something to keep in memory.
const MAX_ANSWER: u64 = 256 << 20;

/// Ask `request` on the socket at `socket`: its whole answer, as bytes.
pub fn ask(socket: &Path, request: &str) -> Result<Vec<u8>, Failure> {
    let mut stream =
        std::os::unix::net::UnixStream::connect(socket).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Failure::Off,
            _ => Failure::Said(format!("служба истории не отвечает: {e}")),
        })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    stream
        .write_all(format!("{request}\n").as_bytes())
        .map_err(|e| Failure::Said(format!("служба истории не отвечает: {e}")))?;
    let mut answer = Vec::new();
    stream
        .take(MAX_ANSWER)
        .read_to_end(&mut answer)
        .map_err(|e| Failure::Said(format!("служба истории не ответила: {e}")))?;
    Ok(answer)
}

/// Ask, and read the answer as text.
pub fn ask_text(socket: &Path, request: &str) -> Result<String, Failure> {
    ask(socket, request).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// `get`'s answer from a reader: `ok⇥<length>\n`, then exactly that many
/// bytes, however the reads split them; fewer is a broken answer, not a
/// short content.
pub fn read_got(mut from: impl Read) -> Result<Vec<u8>, String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match from.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => head.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("служба истории не ответила: {e}")),
        }
        if head.len() > 4096 {
            return Err("служба истории ответила непонятно".to_owned());
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    if let Some(why) = refusal(&head) {
        return Err(why);
    }
    let length: u64 = head
        .strip_prefix("ok\t")
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| format!("служба истории ответила непонятно: «{head}»"))?;
    if length > MAX_ANSWER {
        return Err("ответ службы истории слишком велик".to_owned());
    }
    let mut body = Vec::with_capacity(length as usize);
    from.take(length)
        .read_to_end(&mut body)
        .map_err(|e| format!("служба истории не ответила: {e}"))?;
    if body.len() as u64 != length {
        return Err("ответ службы истории оборвался".to_owned());
    }
    Ok(body)
}

/// Run `f` on a thread of its own — never on the executor's pool, which
/// carries the input — and await what it gives.
pub async fn off_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (done, over) = iced::futures::channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = done.send(f());
    });
    over.await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_round_trip() {
        for text in ["a=b\tc\nd%e", "", "простой текст", "100%", "%25"] {
            assert_eq!(decode(&encode(text)).as_deref(), Some(text));
            assert!(!encode(text).contains(['\t', '\n', '=']));
        }
        assert_eq!(decode("a%2Cb").as_deref(), Some("a,b"));
        assert_eq!(decode("%zz"), None);
        assert_eq!(decode("%4"), None);
    }

    #[test]
    fn a_filter_is_a_search_line() {
        let filter = Filter {
            words: "  привет  мир ".to_owned(),
            re: Some("(?i)\\d{4}=\t".to_owned()),
            types: vec!["text/plain".to_owned(), "image/*".to_owned()],
            copied: Some((10, 20)),
            pasted: None,
            around: Some((100, 5)),
        };
        assert_eq!(
            search_request("main", &filter, Some(7), 50),
            "search\tmain\tq=привет  мир\tre=(?i)\\d{4}%3D%09\ttype=text/plain\t\
             type=image/*\tcopied=10-20\taround=100:5\tbefore=7\tlimit=50"
        );
        assert_eq!(
            search_request("host", &Filter::default(), None, 999),
            "search\thost\tlimit=200"
        );
        assert_eq!(get_request("a", 3, "image/png"), "get\ta\t3\timage/png");
        assert_eq!(move_request("a", 3, "b"), "move\ta\t3\tb");
        assert_eq!(delete_request("a", 3), "delete\ta\t3");
    }

    #[test]
    fn answers_are_read() {
        let got = parse_entries(
            "9\t1000\t3000\t2\t1\t4000\ttext/plain:12,image%2Fx%2Cy:3\tпервая%0Aвторая%09\n\
             8\t500\t500\t1\t0\t0\timage/png:3072\t\n\
             broken line\n",
        )
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].id, 9);
        assert_eq!(
            (got[0].copies, got[0].pastes, got[0].last_pasted),
            (2, 1, 4000)
        );
        assert_eq!(got[0].types[1], ("image/x,y".to_owned(), 3));
        assert_eq!(got[0].preview, "первая\nвторая\t");
        assert_eq!(got[0].text_type(), Some("text/plain"));
        assert_eq!(got[1].image(), Some(&("image/png".to_owned(), 3072)));
        assert_eq!(
            parse_entries("error\tнет такой истории\n"),
            Err("нет такой истории".to_owned())
        );
        assert_eq!(parse_histories("host\nmain\n").unwrap(), ["host", "main"]);
        assert_eq!(parse_ok("ok\t42\n").as_deref(), Ok("42"));
        assert_eq!(parse_ok("ok\n").as_deref(), Ok(""));
        assert!(parse_ok("what\n").is_err());
        assert_eq!(parse_ok("error\tнельзя\n"), Err("нельзя".to_owned()));
    }

    /// A reader that gives at most `chunk` bytes a read.
    struct Trickle(Vec<u8>, usize, usize);

    impl Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.2.min(buf.len()).min(self.0.len() - self.1);
            buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        }
    }

    #[test]
    fn got_bytes_are_read_across_reads() {
        let mut answer = b"ok\t10\n".to_vec();
        answer.extend_from_slice(b"\x89PNG\n\0\t%=x");
        for chunk in [1, 3, 7, 100] {
            let got = read_got(Trickle(answer.clone(), 0, chunk)).unwrap();
            assert_eq!(got, b"\x89PNG\n\0\t%=x");
        }
        assert!(read_got(Trickle(b"ok\t10\nshort".to_vec(), 0, 4)).is_err());
        assert_eq!(
            read_got(Trickle("error\tнет записи\n".as_bytes().to_vec(), 0, 2)),
            Err("нет записи".to_owned())
        );
        assert!(read_got(Trickle(b"ok\tx\n".to_vec(), 0, 2)).is_err());
    }

    /// A daemon of the test's: answers each request from `answers` by its
    /// first word, writing the answer a few bytes at a time.
    fn fake_daemon(
        answers: Vec<(&'static str, Vec<u8>)>,
    ) -> (PathBuf, std::thread::JoinHandle<Vec<String>>) {
        let dir = std::env::temp_dir().join(format!(
            "clipd-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("cellward-clip.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let count = answers.len();
        let server = std::thread::spawn(move || {
            use std::io::BufRead;
            let mut asked = Vec::new();
            for stream in listener.incoming().take(count) {
                let mut stream = stream.unwrap();
                let mut line = String::new();
                std::io::BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let word = line.split('\t').next().unwrap().trim().to_owned();
                let answer = answers
                    .iter()
                    .find(|(w, _)| *w == word)
                    .map(|(_, a)| a.clone())
                    .unwrap_or_else(|| "error\tнепонятный запрос\n".as_bytes().to_vec());
                for piece in answer.chunks(5) {
                    stream.write_all(piece).unwrap();
                    stream.flush().unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
                asked.push(line.trim_end().to_owned());
            }
            asked
        });
        (socket, server)
    }

    #[test]
    fn the_daemon_is_asked_on_its_socket() {
        let mut got = b"ok\t6\n".to_vec();
        got.extend_from_slice(b"a\nb\tc\n");
        let (socket, server) = fake_daemon(vec![
            ("search", b"5\t1\t1\t1\t0\t0\ttext/plain:3\tabc\n".to_vec()),
            ("get", got),
            ("delete", b"ok\n".to_vec()),
        ]);
        let entries = parse_entries(
            &ask_text(
                &socket,
                &search_request("main", &Filter::default(), None, PAGE),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(entries[0].preview, "abc");
        let bytes = ask(&socket, &get_request("main", 5, "text/plain")).unwrap();
        assert_eq!(read_got(bytes.as_slice()).unwrap(), b"a\nb\tc\n");
        assert_eq!(
            parse_ok(&ask_text(&socket, &delete_request("main", 5)).unwrap()).as_deref(),
            Ok("")
        );
        let asked = server.join().unwrap();
        assert_eq!(
            asked,
            [
                "search\tmain\tlimit=50",
                "get\tmain\t5\ttext/plain",
                "delete\tmain\t5"
            ]
        );
        std::fs::remove_dir_all(socket.parent().unwrap()).unwrap();
        // Nobody on the socket: the history is off, said so.
        assert_eq!(ask(&socket, "histories"), Err(Failure::Off));
        assert!(Failure::Off
            .text()
            .contains("programs.cellward.clipboard.history"));
    }
}
