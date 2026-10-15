use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::*;

/// A directory of the test's own, removed after.
struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::var_os("CLIPSTORE_TEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let p = base.join(format!(
            "clipstore-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn key(b: u8) -> Key {
    Key::from_bytes([b; 32])
}

fn text(t: i64, s: &str) -> NewEntry {
    NewEntry {
        copied_at: t,
        contents: vec![
            Content {
                mime: "text/plain;charset=utf-8".into(),
                data: s.as_bytes().to_vec(),
            },
            Content {
                mime: "UTF8_STRING".into(),
                data: s.as_bytes().to_vec(),
            },
        ],
        preview: None,
    }
}

/// Small segments, merges early: every path of the store in a few entries.
fn small() -> Options {
    Options {
        seal_bytes: 2048,
        fanout: 2,
        sync: false,
        auto_merge: true,
    }
}

fn words(h: &History, w: &[&str]) -> Vec<u64> {
    let q = Query {
        text_terms: w.iter().map(|s| s.to_string()).collect(),
        ..Query::default()
    };
    h.query(&q, None, 1000).unwrap()
}

#[test]
fn round_trip_through_log_seal_merge_and_reopen() {
    let d = Tmp::new("rt");
    let k = key(1);
    let image = Content {
        mime: "image/png".into(),
        data: (0..100_000u32).map(|i| (i * 7) as u8).collect(),
    };
    let mut ids = Vec::new();
    {
        let mut h = History::open_with(d.path(), &k, small()).unwrap();
        for i in 0..50 {
            ids.push(
                h.append(text(1000 + i, &format!("entry number {i}")))
                    .unwrap()
                    .id(),
            );
        }
        let img = h
            .append(NewEntry {
                copied_at: 5000,
                contents: vec![image.clone()],
                preview: Some("картинка".into()),
            })
            .unwrap();
        ids.push(img.id());
        assert!(h.stats().segments >= 1, "{:?}", h.stats());
        let e = h.get(ids[7]).unwrap().unwrap();
        assert_eq!(e.contents, text(0, "entry number 7").contents);
        assert_eq!(e.copied_at, 1007);
        assert_eq!(e.copies, vec![1007]);
        assert_eq!(e.preview, "entry number 7");
        let s = h.summary(img.id()).unwrap().unwrap();
        assert_eq!(s.types, vec![("image/png".to_string(), 100_000)]);
        assert_eq!(s.preview, "картинка");
    }
    let h = History::open_with(d.path(), &k, small()).unwrap();
    for (i, &id) in ids.iter().take(50).enumerate() {
        let e = h.get(id).unwrap().unwrap();
        assert_eq!(e.contents[0].data, format!("entry number {i}").as_bytes());
    }
    assert_eq!(h.get(ids[50]).unwrap().unwrap().contents, vec![image]);
    // Ids grow: the newest first ("number 4" is in 4 and 40..49).
    let mut expect: Vec<u64> = ids[40..50].iter().rev().copied().collect();
    expect.push(ids[4]);
    assert_eq!(words(&h, &["number 4"]), expect);
    assert_eq!(h.get(9999).unwrap(), None);
}

#[test]
fn a_torn_tail_is_cut_off() {
    let d = Tmp::new("crash");
    let k = key(2);
    {
        let mut h = History::open(d.path(), &k).unwrap();
        h.append(text(1, "first one")).unwrap();
        h.append(text(2, "second one")).unwrap();
        h.append(text(3, "third one")).unwrap();
    }
    let log = fs::read_dir(d.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "cwl"))
        .unwrap();
    let len = fs::metadata(&log).unwrap().len();
    // Into the middle of the last record.
    fs::OpenOptions::new()
        .write(true)
        .open(&log)
        .unwrap()
        .set_len(len - 20)
        .unwrap();
    let mut h = History::open(d.path(), &k).unwrap();
    assert_eq!(words(&h, &["one"]), vec![2, 1]);
    assert!(words(&h, &["third"]).is_empty());
    let id = h.append(text(4, "fourth one")).unwrap().id();
    assert_eq!(h.get(id).unwrap().unwrap().copied_at, 4);
    drop(h);
    let h = History::open(d.path(), &k).unwrap();
    assert_eq!(words(&h, &["one"]), vec![id, 2, 1]);

    // A flipped byte in a frame: that frame and what follows are the tail.
    drop(h);
    let mut b = fs::read(&log).unwrap();
    let n = b.len();
    b[n - 30] ^= 0xff;
    fs::write(&log, b).unwrap();
    let h = History::open(d.path(), &k).unwrap();
    assert_eq!(words(&h, &["one"]), vec![2, 1]);
}

#[test]
fn copying_again_is_an_event_not_an_entry() {
    let d = Tmp::new("dedup");
    let k = key(3);
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    let a = h.append(text(10, "same text")).unwrap();
    assert!(matches!(a, Appended::New(_)));
    for i in 0..40 {
        h.append(text(20 + i, &format!("filler {i}"))).unwrap();
    }
    // The first is sealed by now: dedup finds it in a segment.
    assert!(h.stats().segments > 0);
    let b = h.append(text(100, "same text")).unwrap();
    assert_eq!(b, Appended::Again(a.id()));
    // The same contents offered in another order are the same.
    let mut swapped = text(110, "same text");
    swapped.contents.reverse();
    assert_eq!(h.append(swapped).unwrap(), Appended::Again(a.id()));
    assert!(matches!(
        h.append(text(120, "Same text")).unwrap(),
        Appended::New(_)
    ));
    let e = h.get(a.id()).unwrap().unwrap();
    assert_eq!(e.copies, vec![10, 100, 110]);
    assert_eq!(e.copied_at, 10);
    // Deleted, it is not copied "again".
    assert!(h.delete(a.id()).unwrap());
    let c = h.append(text(130, "same text")).unwrap();
    assert!(matches!(c, Appended::New(id) if id > a.id()));
}

#[test]
fn delete_hides_at_once_and_a_merge_drops_it() {
    let d = Tmp::new("del");
    let k = key(4);
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    let mut ids = Vec::new();
    for i in 0..30 {
        ids.push(h.append(text(i, &format!("doomed word{i}"))).unwrap().id());
    }
    let last = h.append(text(99, "doomed last")).unwrap().id();
    assert!(h.delete(ids[3]).unwrap());
    assert!(h.delete(last).unwrap());
    assert!(!h.delete(last).unwrap());
    assert!(!h.record_paste(last, 5).unwrap());
    assert_eq!(h.get(ids[3]).unwrap(), None);
    let found = words(&h, &["doomed"]);
    assert!(!found.contains(&ids[3]) && !found.contains(&last));
    assert_eq!(found.len(), 29);
    h.compact().unwrap();
    assert_eq!(h.stats().segments, 1);
    assert_eq!(h.stats().sealed_entries, 29);
    assert_eq!(words(&h, &["doomed"]).len(), 29);
    // The newest id is never handed out again.
    let next = h.append(text(200, "after")).unwrap().id();
    assert!(next > last);
    drop(h);
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    assert!(h.append(text(201, "after again")).unwrap().id() > next);
    assert_eq!(h.get(ids[3]).unwrap(), None);
}

#[test]
fn date_ranges_and_pastes() {
    let d = Tmp::new("dates");
    let k = key(5);
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    let day = 86_400_000i64;
    let mut ids = Vec::new();
    for i in 0..60 {
        ids.push(
            h.append(text(i * day / 4, &format!("item {i}")))
                .unwrap()
                .id(),
        );
    }
    // Day 3: items 12..16.
    let q = Query {
        copied: Some(3 * day..4 * day),
        ..Query::default()
    };
    assert_eq!(
        h.query(&q, None, 100).unwrap(),
        vec![ids[15], ids[14], ids[13], ids[12]]
    );
    // Paged.
    assert_eq!(h.query(&q, None, 2).unwrap(), vec![ids[15], ids[14]]);
    assert_eq!(
        h.query(&q, Some(ids[14]), 2).unwrap(),
        vec![ids[13], ids[12]]
    );
    // Copied again on day 20: it is in day 20's copies too.
    assert!(h.record_copy(ids[2], 20 * day + 5).unwrap());
    let q20 = Query {
        copied: Some(20 * day..21 * day),
        ..Query::default()
    };
    assert_eq!(h.query(&q20, None, 100).unwrap(), vec![ids[2]]);
    // Pastes.
    assert!(h.record_paste(ids[1], 30 * day).unwrap());
    assert!(h.record_paste(ids[40], 30 * day + 1).unwrap());
    h.seal().unwrap();
    assert!(h.record_paste(ids[41], 31 * day).unwrap());
    let qp = Query {
        pasted: Some(30 * day..32 * day),
        ..Query::default()
    };
    assert_eq!(
        h.query(&qp, None, 100).unwrap(),
        vec![ids[41], ids[40], ids[1]]
    );
    let qp = Query {
        pasted: Some(30 * day..32 * day),
        text_terms: vec!["ITEM 4".into()],
        ..Query::default()
    };
    assert_eq!(h.query(&qp, None, 100).unwrap(), vec![ids[41], ids[40]]);
    assert_eq!(h.get(ids[1]).unwrap().unwrap().pastes, vec![30 * day]);
    // Around a time: copies and pastes within the window.
    let qa = Query {
        around: Some((30 * day, 1000)),
        ..Query::default()
    };
    assert_eq!(h.query(&qa, None, 100).unwrap(), vec![ids[40], ids[1]]);
    // Both kinds at once must both hold.
    let qb = Query {
        copied: Some(0..day),
        pasted: Some(30 * day..31 * day),
        ..Query::default()
    };
    assert_eq!(h.query(&qb, None, 100).unwrap(), vec![ids[1]]);
}

#[test]
fn patterns_types_and_paging_over_segments() {
    let d = Tmp::new("query");
    let k = key(6);
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    let mut all = Vec::new();
    for i in 0..200 {
        let s = format!(
            "Order #{:05} for Ünïcode Привет {}",
            i * 37,
            if i % 10 == 0 { "rare-marker" } else { "x" }
        );
        all.push(h.append(text(i, &s)).unwrap().id());
    }
    let png = h
        .append(NewEntry {
            copied_at: 500,
            contents: vec![Content {
                mime: "image/png".into(),
                data: vec![1, 2, 3],
            }],
            preview: None,
        })
        .unwrap()
        .id();
    assert!(h.stats().segments >= 2, "{:?}", h.stats());

    let rare = words(&h, &["RARE-marker"]);
    assert_eq!(rare.len(), 20);
    assert_eq!(rare[0], all[190]);
    assert_eq!(words(&h, &["привет", "ünïcode"]).len(), 200);
    assert_eq!(words(&h, &["#00037"]), vec![all[1]]);
    // A word shorter than a trigram: checked without the index.
    assert_eq!(words(&h, &["#0"]).len(), 200);

    let pat = |p: &str| {
        h.query(
            &Query {
                pattern: Some(p.into()),
                ..Query::default()
            },
            None,
            1000,
        )
        .unwrap()
    };
    assert_eq!(pat(r"Order #0007\d for"), vec![all[2]]);
    assert_eq!(pat(r"(?i)ORDER #00000"), vec![all[0]]);
    assert_eq!(pat(r"^Order #\d+ for .* rare-marker$").len(), 20);
    // Case matters in a pattern without (?i).
    assert!(pat(r"order #").is_empty());
    assert!(matches!(
        h.query(
            &Query {
                pattern: Some("(".into()),
                ..Query::default()
            },
            None,
            1
        ),
        Err(Error::BadPattern(_))
    ));

    let ty = |t: &[&str]| {
        h.query(
            &Query {
                types: Some(t.iter().map(|s| s.to_string()).collect()),
                ..Query::default()
            },
            None,
            1000,
        )
        .unwrap()
    };
    assert_eq!(ty(&["image/*"]), vec![png]);
    assert_eq!(ty(&["IMAGE/PNG"]), vec![png]);
    assert_eq!(ty(&["image/jpeg"]), Vec::<u64>::new());
    assert_eq!(ty(&["text/*", "image/png"]).len(), 201);

    // Every entry, a page at a time, newest first, each once.
    let mut seen = Vec::new();
    let mut before = None;
    loop {
        let page = h.query(&Query::default(), before, 7).unwrap();
        if page.is_empty() {
            break;
        }
        before = page.last().copied();
        seen.extend(page);
    }
    let mut expect = all.clone();
    expect.push(png);
    expect.reverse();
    assert_eq!(seen, expect);
}

#[test]
fn a_wrong_key_is_told() {
    let d = Tmp::new("wrongkey");
    {
        let mut h = History::open(d.path(), &key(7)).unwrap();
        h.append(text(1, "secret")).unwrap();
    }
    let e = History::open(d.path(), &key(8)).err().unwrap();
    assert!(matches!(e, Error::WrongKey));
    assert!(e.to_string().contains("ключ не от этой истории"), "{e}");
    assert!(History::open(d.path(), &key(7)).is_ok());
}

#[test]
fn one_process_at_a_time() {
    let d = Tmp::new("busy");
    let _h = History::open(d.path(), &key(9)).unwrap();
    assert!(matches!(History::open(d.path(), &key(9)), Err(Error::Busy)));
}

#[test]
fn nothing_of_the_text_is_on_disk() {
    let d = Tmp::new("plain");
    let k = key(10);
    let word = "quokkazanzibar";
    let mut h = History::open_with(d.path(), &k, small()).unwrap();
    for i in 0..40 {
        h.append(text(i, &format!("{word} {i} text/plain")))
            .unwrap();
    }
    let big = format!("{word} ").repeat(2000);
    h.append(text(100, &big)).unwrap();
    h.append(NewEntry {
        copied_at: 101,
        contents: vec![Content {
            mime: "image/x-secret-type".into(),
            data: word.as_bytes().to_vec(),
        }],
        preview: Some(format!("preview {word}")),
    })
    .unwrap();
    h.seal().unwrap();
    h.append(text(102, word)).unwrap();
    assert!(h.stats().segments >= 1 && h.stats().active_entries == 1);
    drop(h);
    let needles: [&[u8]; 4] = [word.as_bytes(), b"zanzib", b"text/plain", b"x-secret"];
    for e in fs::read_dir(d.path()).unwrap().flatten() {
        let b = fs::read(e.path()).unwrap();
        for n in needles {
            assert!(
                !b.windows(n.len()).any(|w| w == n),
                "{:?} found in {}",
                String::from_utf8_lossy(n),
                e.path().display()
            );
        }
    }
    // And it is all still there.
    let h = History::open_with(d.path(), &k, small()).unwrap();
    assert_eq!(words(&h, &[word]).len(), 42);
}

#[test]
fn moving_an_entry_to_another_history() {
    let a_dir = Tmp::new("mv-a");
    let b_dir = Tmp::new("mv-b");
    let mut a = History::open(a_dir.path(), &key(11)).unwrap();
    let mut b = History::open(b_dir.path(), &key(12)).unwrap();
    let id = a.append(text(5, "moving out")).unwrap().id();
    a.record_copy(id, 6).unwrap();
    a.record_paste(id, 7).unwrap();
    let e = a.get(id).unwrap().unwrap();
    let new = b.import(&e).unwrap().id();
    assert!(a.delete(id).unwrap());
    let moved = b.get(new).unwrap().unwrap();
    assert_eq!(moved.contents, e.contents);
    assert_eq!(moved.copies, vec![5, 6]);
    assert_eq!(moved.pastes, vec![7]);
    assert_eq!(moved.preview, "moving out");
    assert!(words(&a, &["moving"]).is_empty());
    assert_eq!(words(&b, &["moving"]), vec![new]);
}

#[test]
fn an_entry_has_a_cap() {
    let d = Tmp::new("cap");
    let mut h = History::open(d.path(), &key(13)).unwrap();
    let e = NewEntry {
        copied_at: 0,
        contents: vec![Content {
            mime: "application/octet-stream".into(),
            data: vec![0; MAX_ENTRY + 1],
        }],
        preview: None,
    };
    assert!(matches!(h.append(e), Err(Error::TooLarge(_))));
}

#[test]
fn the_key_file() {
    let d = Tmp::new("key");
    let p = d.path().join("key");
    let k1 = Key::load_or_create(&p).unwrap();
    let meta = fs::metadata(&p).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 32);
    let k2 = Key::load_or_create(&p).unwrap();
    assert_eq!(k1.bytes(), k2.bytes());
    assert_ne!(k1.bytes(), &[0u8; 32]);
    assert_eq!(format!("{k1:?}"), "Key(..)");

    // Readable by others: refused.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Key::load_or_create(&p), Err(Error::KeyFile(_))));
    // The wrong size: refused.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&p, b"short").unwrap();
    assert!(matches!(Key::load_or_create(&p), Err(Error::KeyFile(_))));
}

#[test]
fn a_link_in_place_of_the_key_is_not_followed() {
    let d = Tmp::new("keylink");
    // A link to an existing file: not read, not used.
    let target = d.path().join("planted");
    fs::write(&target, [0x42u8; 32]).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let p = d.path().join("key");
    symlink(&target, &p).unwrap();
    let e = Key::load_or_create(&p).unwrap_err();
    assert!(matches!(e, Error::KeyFile(_)), "{e}");
    assert!(e.to_string().contains("ссылка"), "{e}");
    // A dangling link: the file it points to is not made.
    let p2 = d.path().join("key2");
    let nowhere = d.path().join("would-be-made");
    symlink(&nowhere, &p2).unwrap();
    assert!(Key::load_or_create(&p2).is_err());
    assert!(!nowhere.exists());
    assert_eq!(fs::read(&target).unwrap(), [0x42u8; 32]);
}

/// Damage to a sealed blob makes that entry fail to decrypt — said, not
/// garbage — and leaves the others.
#[test]
fn an_altered_entry_does_not_decrypt() {
    let d = Tmp::new("alter");
    let k = key(14);
    let mut h = History::open(d.path(), &k).unwrap();
    let a = h.append(text(1, "alpha entry")).unwrap().id();
    let b = h.append(text(2, "beta entry")).unwrap().id();
    h.seal().unwrap();
    drop(h);
    let seg = fs::read_dir(d.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "cws"))
        .unwrap();
    let mut bytes = fs::read(&seg).unwrap();
    // The records section starts after the header and the locations: flip
    // a byte of the first blob's ciphertext.
    let at = segment_records_start(&bytes) + 80;
    bytes[at] ^= 1;
    fs::write(&seg, bytes).unwrap();
    let h = History::open(d.path(), &k).unwrap();
    assert!(matches!(h.get(a), Err(Error::Undecryptable(id)) if id == a));
    assert!(h.get(b).unwrap().is_some());
    assert_eq!(words(&h, &["entry"]), vec![b]);
}

fn segment_records_start(b: &[u8]) -> usize {
    codec::u64_at(b, 32 + segment::S_RECORDS * 16).unwrap() as usize
}

/// The measure of the store at scale (ignored by default; in release:
/// `CLIPSTORE_BENCH_N=10000000 CLIPSTORE_TEST_DIR=<a disk, not tmpfs>
/// cargo test --release -- --ignored --nocapture bench`).
#[test]
#[ignore]
fn bench_ten_million() {
    let n: u64 = std::env::var("CLIPSTORE_BENCH_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_000);
    let d = Tmp::new("bench");
    let k = key(15);
    let opts = Options {
        seal_bytes: 32 << 20,
        fanout: 8,
        sync: false,
        auto_merge: true,
    };
    // A vocabulary of random words, used Zipf-like: a few very common, most
    // rare.
    let mut rng = 0x9e3779b97f4a7c15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let vocab: Vec<String> = (0..50_000)
        .map(|_| {
            let len = 3 + (next() % 8) as usize;
            (0..len)
                .map(|_| (b'a' + (next() % 26) as u8) as char)
                .collect()
        })
        .collect();
    let start_ms = 1_700_000_000_000i64;
    let step = 3_000i64; // 10 M copies over a year
    let mut h = History::open_with(d.path(), &k, opts.clone()).unwrap();
    let t0 = Instant::now();
    let mut seal_time = std::time::Duration::ZERO;
    for i in 0..n {
        let nw = 3 + (next() % 6) as usize;
        let mut s = String::new();
        for _ in 0..nw {
            // Zipf-ish: the square of a uniform picks low ranks often.
            let u = (next() % 1_000_000) as f64 / 1_000_000.0;
            let r = ((u * u * u) * vocab.len() as f64) as usize;
            if !s.is_empty() {
                s.push(' ');
            }
            s.push_str(&vocab[r]);
        }
        s.push_str(&format!(" {i}"));
        let before = h.stats().segments;
        let ts = Instant::now();
        h.append(text(start_ms + i as i64 * step, &s)).unwrap();
        if h.stats().segments != before {
            seal_time += ts.elapsed();
        }
        if i % 10 == 0 {
            h.record_paste(i + 1, start_ms + i as i64 * step + 500)
                .unwrap();
        }
        if i > 0 && i % 1_000_000 == 0 {
            eprintln!(
                "{i} entries, {:.1}s, {:?}",
                t0.elapsed().as_secs_f64(),
                h.stats()
            );
        }
    }
    let total = t0.elapsed();
    eprintln!(
        "append: {n} entries in {:.1}s = {:.0}/s (of which seal+merge {:.1}s)",
        total.as_secs_f64(),
        n as f64 / total.as_secs_f64(),
        seal_time.as_secs_f64()
    );
    let ts = Instant::now();
    h.compact().unwrap();
    eprintln!(
        "compact (seal + merge all): {:.1}s",
        ts.elapsed().as_secs_f64()
    );
    eprintln!("stats: {:?}", h.stats());
    drop(h);

    let ts = Instant::now();
    let h = History::open_with(d.path(), &k, opts.clone()).unwrap();
    eprintln!("open: {:?}", ts.elapsed());

    let time = |label: &str, q: &Query| {
        let ts = Instant::now();
        let page = h.query(q, None, 50).unwrap();
        let first = ts.elapsed();
        let ts = Instant::now();
        let next = page
            .last()
            .map(|&b| h.query(q, Some(b), 50).unwrap().len())
            .unwrap_or(0);
        eprintln!(
            "query {label}: first page {} ids in {:?}; next page {} in {:?}",
            page.len(),
            first,
            next,
            ts.elapsed()
        );
    };
    let rare = vocab.last().unwrap().clone();
    let common = vocab[0].clone();
    time(
        &format!("rare word {rare:?}"),
        &Query {
            text_terms: vec![rare.clone()],
            ..Query::default()
        },
    );
    time(
        &format!("common word {common:?}"),
        &Query {
            text_terms: vec![common.clone()],
            ..Query::default()
        },
    );
    time(
        "two common words",
        &Query {
            text_terms: vec![common.clone(), vocab[1].clone()],
            ..Query::default()
        },
    );
    let day = 86_400_000;
    time(
        "one day",
        &Query {
            copied: Some(start_ms + 100 * day..start_ms + 101 * day),
            ..Query::default()
        },
    );
    time(
        "pasted, one hour",
        &Query {
            pasted: Some(start_ms + 200 * day..start_ms + 200 * day + 3_600_000),
            ..Query::default()
        },
    );
    time(
        "rare word in a month",
        &Query {
            text_terms: vec![vocab[40_000].clone()],
            copied: Some(start_ms + 30 * day..start_ms + 60 * day),
            ..Query::default()
        },
    );
    time(
        &format!("regex {common}\\s+\\d{{4}}$"),
        &Query {
            pattern: Some(format!(r"{common}\s+\d{{4}}$")),
            ..Query::default()
        },
    );
    time(
        &format!("regex rare {rare} \\d+"),
        &Query {
            pattern: Some(format!(r"{rare} \d+")),
            ..Query::default()
        },
    );
    let ts = Instant::now();
    let mut c = 0;
    let mut b = None;
    loop {
        let p = h
            .query(
                &Query {
                    text_terms: vec![rare.clone()],
                    ..Query::default()
                },
                b,
                1000,
            )
            .unwrap();
        if p.is_empty() {
            break;
        }
        c += p.len();
        b = p.last().copied();
    }
    eprintln!("all matches of the rare word: {c} in {:?}", ts.elapsed());
}
