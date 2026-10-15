//! The history window's pattern builder: a regular expression put together
//! from blocks — a text, a letter, a number in a range… — instead of typed,
//! said back in words, and tried live on a text the person types. What it
//! builds is a search's `re` (Rust's `regex`, which the daemon matches with).
//!
//! The blocks are those of the owner's own regex builder: each with its
//! parameters and how many times it repeats (greedy, or as few as can be),
//! in an order the person changes; three flags — any case, `^`/`$` at every
//! line, `.` across lines — written as inline flags at the pattern's start,
//! the one string the search carries.
//!
//! `regex` has no look-around: a number "on its own" (not a part of a longer
//! one) is guarded by a non-digit, or the text's start or end, consumed —
//! and only on a side where no block of the person's stands, so that `порт `
//! then a number still matches «порт 25». A match there takes that one
//! character more, which the live test shows as it is.

use std::ops::Range;

/// Which letters a letter block takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    Any,
    Latin,
    Cyrillic,
}

impl Alphabet {
    pub const ALL: [Alphabet; 3] = [Alphabet::Any, Alphabet::Latin, Alphabet::Cyrillic];
}

impl std::fmt::Display for Alphabet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Alphabet::Any => "любая",
            Alphabet::Latin => "латиница",
            Alphabet::Cyrillic => "кириллица",
        })
    }
}

/// A block, with its parameters as the person typed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Text(String),
    AnyChar,
    Letter(Alphabet),
    Digit,
    /// From, to (as typed), and whether it is a number of its own.
    Number(String, String, bool),
    OneOf(String),
    NoneOf(String),
    Space,
    WordChar,
    LineStart,
    LineEnd,
    WordBoundary,
}

/// The palette: what a block starts as, and its name — grouped as the
/// owner's builder groups them.
pub const PALETTE: [(&str, &[Tag]); 3] = [
    (
        "Текст и символы",
        &[
            Tag::Text,
            Tag::AnyChar,
            Tag::Letter,
            Tag::OneOf,
            Tag::NoneOf,
            Tag::Space,
            Tag::WordChar,
        ],
    ),
    ("Числа", &[Tag::Digit, Tag::Number]),
    (
        "Позиции",
        &[Tag::LineStart, Tag::LineEnd, Tag::WordBoundary],
    ),
];

/// A kind of block without its parameters: a button of the palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Text,
    AnyChar,
    Letter,
    Digit,
    Number,
    OneOf,
    NoneOf,
    Space,
    WordChar,
    LineStart,
    LineEnd,
    WordBoundary,
}

impl Tag {
    pub fn name(self) -> &'static str {
        match self {
            Tag::Text => "Текст",
            Tag::AnyChar => "Любой символ",
            Tag::Letter => "Буква",
            Tag::Digit => "Цифра",
            Tag::Number => "Число в диапазоне",
            Tag::OneOf => "Один из символов",
            Tag::NoneOf => "Ни один из символов",
            Tag::Space => "Пробел / отступ",
            Tag::WordChar => "Буква/цифра/подчёркивание",
            Tag::LineStart => "Начало строки",
            Tag::LineEnd => "Конец строки",
            Tag::WordBoundary => "Граница слова",
        }
    }

    /// A new block of this kind.
    pub fn block(self) -> Kind {
        match self {
            Tag::Text => Kind::Text("abc".to_owned()),
            Tag::AnyChar => Kind::AnyChar,
            Tag::Letter => Kind::Letter(Alphabet::Any),
            Tag::Digit => Kind::Digit,
            Tag::Number => Kind::Number("0".to_owned(), "20".to_owned(), true),
            Tag::OneOf => Kind::OneOf("ABC".to_owned()),
            Tag::NoneOf => Kind::NoneOf("ABC".to_owned()),
            Tag::Space => Kind::Space,
            Tag::WordChar => Kind::WordChar,
            Tag::LineStart => Kind::LineStart,
            Tag::LineEnd => Kind::LineEnd,
            Tag::WordBoundary => Kind::WordBoundary,
        }
    }
}

impl Kind {
    pub fn tag(&self) -> Tag {
        match self {
            Kind::Text(_) => Tag::Text,
            Kind::AnyChar => Tag::AnyChar,
            Kind::Letter(_) => Tag::Letter,
            Kind::Digit => Tag::Digit,
            Kind::Number(..) => Tag::Number,
            Kind::OneOf(_) => Tag::OneOf,
            Kind::NoneOf(_) => Tag::NoneOf,
            Kind::Space => Tag::Space,
            Kind::WordChar => Tag::WordChar,
            Kind::LineStart => Tag::LineStart,
            Kind::LineEnd => Tag::LineEnd,
            Kind::WordBoundary => Tag::WordBoundary,
        }
    }

    /// A position, not a character: nothing to repeat, nothing consumed.
    pub fn is_position(&self) -> bool {
        matches!(self, Kind::LineStart | Kind::LineEnd | Kind::WordBoundary)
    }
}

/// How many times a block repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Times {
    One,
    Optional,
    Any,
    Some,
    Exactly,
    Between,
    AtLeast,
}

impl Times {
    pub const ALL: [Times; 7] = [
        Times::One,
        Times::Optional,
        Times::Any,
        Times::Some,
        Times::Exactly,
        Times::Between,
        Times::AtLeast,
    ];
}

impl std::fmt::Display for Times {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Times::One => "ровно 1",
            Times::Optional => "0 или 1",
            Times::Any => "0 или больше",
            Times::Some => "1 или больше",
            Times::Exactly => "ровно N раз",
            Times::Between => "от N до M раз",
            Times::AtLeast => "N раз и больше",
        })
    }
}

/// A block of the sequence: what, how many times, `n`/`m` as typed, and
/// whether as few as can be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub kind: Kind,
    pub times: Times,
    pub n: String,
    pub m: String,
    pub lazy: bool,
}

impl Block {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            times: Times::One,
            n: "1".to_owned(),
            m: "3".to_owned(),
            lazy: false,
        }
    }

    fn n(&self) -> u32 {
        self.n.trim().parse().unwrap_or(0)
    }

    fn m(&self) -> u32 {
        self.m.trim().parse().unwrap_or(0)
    }

    /// `?`, `{2,5}`, … — nothing for a position, or once.
    fn suffix(&self) -> String {
        if self.kind.is_position() {
            return String::new();
        }
        let (n, m) = (self.n(), self.m());
        let mut s = match self.times {
            Times::One => return String::new(),
            Times::Optional => "?".to_owned(),
            Times::Any => "*".to_owned(),
            Times::Some => "+".to_owned(),
            Times::Exactly => format!("{{{n}}}"),
            Times::Between => format!("{{{},{}}}", n.min(m), n.max(m)),
            Times::AtLeast => format!("{{{n},}}"),
        };
        if self.lazy {
            s.push('?');
        }
        s
    }

    /// How many times, in words — empty for once.
    fn times_words(&self) -> String {
        if self.kind.is_position() {
            return String::new();
        }
        let (n, m) = (self.n(), self.m());
        let words = match self.times {
            Times::One => return String::new(),
            Times::Optional => "необязательно, 0 или 1 раз".to_owned(),
            Times::Any => "0 или больше раз".to_owned(),
            Times::Some => "1 или больше раз".to_owned(),
            Times::Exactly => format!("ровно {n} {}", times_word(n)),
            Times::Between => format!("от {} до {} раз", n.min(m), n.max(m)),
            Times::AtLeast => format!("{n} {} и больше", times_word(n)),
        };
        if self.lazy {
            format!(" ({words}, как можно меньше)")
        } else {
            format!(" ({words})")
        }
    }
}

/// «раз»/«раза» after a number.
fn times_word(n: u32) -> &'static str {
    match (n % 10, n % 100) {
        (2..=4, r) if !(12..=14).contains(&r) => "раза",
        _ => "раз",
    }
}

/// The characters of a class escaped: everything `regex` gives a meaning
/// inside `[…]` (its set operations `&&`, `--`, `~~` among them).
fn escape_in_class(chars: &str) -> String {
    let mut out = String::new();
    for c in chars.chars() {
        if matches!(c, '\\' | ']' | '[' | '^' | '-' | '&' | '~') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The numbers `[lo, hi]` of one length as a pattern of digits.
fn same_length(lo: &str, hi: &str) -> String {
    if lo == hi {
        return lo.to_owned();
    }
    let (a, b) = (lo.as_bytes()[0], hi.as_bytes()[0]);
    if lo.len() == 1 {
        return format!("[{}-{}]", a as char, b as char);
    }
    if a == b {
        return format!("{}{}", a as char, same_length(&lo[1..], &hi[1..]));
    }
    let rest = lo.len() - 1;
    let mut parts = vec![format!(
        "{}{}",
        a as char,
        same_length(&lo[1..], &"9".repeat(rest))
    )];
    if b - a > 1 {
        let (x, y) = ((a + 1) as char, (b - 1) as char);
        let class = if x == y {
            x.to_string()
        } else {
            format!("[{x}-{y}]")
        };
        parts.push(format!("{class}{}", "[0-9]".repeat(rest)));
    }
    parts.push(format!(
        "{}{}",
        b as char,
        same_length(&"0".repeat(rest), &hi[1..])
    ));
    format!("(?:{})", parts.join("|"))
}

/// The numbers `[from, to]` (either order) as a pattern: split where the
/// count of digits changes, each part digit by digit.
pub fn range_pattern(from: u64, to: u64) -> String {
    let (mut lo, hi) = (from.min(to), from.max(to));
    let mut parts = Vec::new();
    loop {
        let len = lo.to_string().len() as u32;
        let top = 10u64.checked_pow(len).map_or(u64::MAX, |p| p - 1).min(hi);
        parts.push(same_length(&lo.to_string(), &top.to_string()));
        if top >= hi {
            break;
        }
        lo = top + 1;
    }
    if parts.len() == 1 {
        parts.pop().unwrap_or_default()
    } else {
        format!("(?:{})", parts.join("|"))
    }
}

/// The builder: the blocks, the flags, the text to try them on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Builder {
    pub blocks: Vec<Block>,
    pub any_case: bool,
    pub every_line: bool,
    pub dot_all: bool,
    pub sample: String,
}

/// What the live test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tried {
    /// Nothing to try: no block, or no text.
    Nothing,
    /// The pattern does not compile: why.
    Broken(String),
    /// The matches' byte ranges in the sample.
    Found(Vec<Range<usize>>),
}

/// More than this many matches are not looked for.
const MAX_MATCHES: usize = 5000;

impl Builder {
    pub fn add(&mut self, tag: Tag) {
        self.blocks.push(Block::new(tag.block()));
    }

    pub fn remove(&mut self, i: usize) {
        if i < self.blocks.len() {
            self.blocks.remove(i);
        }
    }

    /// Block `i` one place up (`-1`) or down (`1`); nothing past the ends.
    pub fn shift(&mut self, i: usize, by: isize) {
        let j = i as isize + by;
        if i < self.blocks.len() && j >= 0 && (j as usize) < self.blocks.len() {
            self.blocks.swap(i, j as usize);
        }
    }

    /// Whether a block that consumes characters stands before, after `i`.
    fn neighbours(&self, i: usize) -> (bool, bool) {
        let consumes = |b: &Block| !b.kind.is_position();
        (
            self.blocks[..i].iter().any(consumes),
            self.blocks[i + 1..].iter().any(consumes),
        )
    }

    /// Block `i`'s pattern, its repetition included.
    fn block_pattern(&self, i: usize) -> String {
        let block = &self.blocks[i];
        let (base, single) = match &block.kind {
            Kind::Text(t) => (regex::escape(t), t.chars().count() == 1),
            Kind::AnyChar => (".".to_owned(), true),
            Kind::Letter(Alphabet::Any) => ("[a-zA-Zа-яА-ЯёЁ]".to_owned(), true),
            Kind::Letter(Alphabet::Latin) => ("[a-zA-Z]".to_owned(), true),
            Kind::Letter(Alphabet::Cyrillic) => ("[а-яА-ЯёЁ]".to_owned(), true),
            Kind::Digit => ("[0-9]".to_owned(), true),
            Kind::Number(from, to, alone) => {
                let from = from.trim().parse().unwrap_or(0);
                let to = to.trim().parse().unwrap_or(0);
                let range = range_pattern(from, to);
                let (before, after) = self.neighbours(i);
                let left = if *alone && !before {
                    "(?:^|[^0-9])"
                } else {
                    ""
                };
                let right = if *alone && !after { "(?:[^0-9]|$)" } else { "" };
                if left.is_empty() && right.is_empty() {
                    // A group of its own, a class, or one digit needs no
                    // group to repeat; digits in a row ("12") do.
                    let single =
                        range.starts_with("(?:") || range.starts_with('[') || range.len() == 1;
                    (range, single)
                } else {
                    (format!("{left}{range}{right}"), false)
                }
            }
            Kind::OneOf(c) => (format!("[{}]", escape_in_class(c)), true),
            Kind::NoneOf(c) => (format!("[^{}]", escape_in_class(c)), true),
            Kind::Space => ("\\s".to_owned(), true),
            Kind::WordChar => ("\\w".to_owned(), true),
            Kind::LineStart => ("^".to_owned(), true),
            Kind::LineEnd => ("$".to_owned(), true),
            Kind::WordBoundary => ("\\b".to_owned(), true),
        };
        let suffix = block.suffix();
        if suffix.is_empty() || single {
            format!("{base}{suffix}")
        } else {
            format!("(?:{base}){suffix}")
        }
    }

    /// The pattern the blocks make, without the flags.
    pub fn body(&self) -> String {
        (0..self.blocks.len())
            .map(|i| self.block_pattern(i))
            .collect()
    }

    /// The flags as `regex` writes them inline: `(?ims)`, or nothing.
    pub fn flags(&self) -> String {
        let f: String = [
            (self.any_case, 'i'),
            (self.every_line, 'm'),
            (self.dot_all, 's'),
        ]
        .into_iter()
        .filter_map(|(on, c)| on.then_some(c))
        .collect();
        if f.is_empty() {
            f
        } else {
            format!("(?{f})")
        }
    }

    /// The whole pattern, the search's `re`: empty with no block.
    pub fn pattern(&self) -> String {
        if self.blocks.is_empty() {
            return String::new();
        }
        format!("{}{}", self.flags(), self.body())
    }

    /// Each block in words, in order.
    pub fn explain(&self) -> Vec<String> {
        self.blocks
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let what = match &b.kind {
                    Kind::Text(t) => format!("текст «{t}»"),
                    Kind::AnyChar => "любой символ".to_owned(),
                    Kind::Letter(a) => format!("буква ({a})"),
                    Kind::Digit => "цифра (0-9)".to_owned(),
                    Kind::Number(from, to, alone) => {
                        let from: u64 = from.trim().parse().unwrap_or(0);
                        let to: u64 = to.trim().parse().unwrap_or(0);
                        let (lo, hi) = (from.min(to), from.max(to));
                        let (before, after) = self.neighbours(i);
                        if *alone && !(before && after) {
                            format!("число от {lo} до {hi}, отдельное — рядом нет других цифр")
                        } else {
                            format!("число от {lo} до {hi}")
                        }
                    }
                    Kind::OneOf(c) => format!("один из символов: {c}"),
                    Kind::NoneOf(c) => format!("любой символ, кроме: {c}"),
                    Kind::Space => "пробел, таб или перенос строки".to_owned(),
                    Kind::WordChar => "буква, цифра или подчёркивание".to_owned(),
                    Kind::LineStart if self.every_line => "начало строки".to_owned(),
                    Kind::LineStart => "начало текста".to_owned(),
                    Kind::LineEnd if self.every_line => "конец строки".to_owned(),
                    Kind::LineEnd => "конец текста".to_owned(),
                    Kind::WordBoundary => "граница слова".to_owned(),
                };
                format!("{what}{}", b.times_words())
            })
            .collect()
    }

    /// The flags in words.
    pub fn flags_words(&self) -> Vec<&'static str> {
        let mut words = Vec::new();
        if self.any_case {
            words.push("без учёта регистра");
        }
        if self.dot_all {
            words.push("«любой символ» включает перенос строки");
        }
        words
    }

    /// The pattern tried on the sample.
    pub fn try_it(&self) -> Tried {
        let pattern = self.pattern();
        if pattern.is_empty() {
            return Tried::Nothing;
        }
        let re = match regex::Regex::new(&pattern) {
            Ok(re) => re,
            Err(e) => return Tried::Broken(e.to_string()),
        };
        if self.sample.is_empty() {
            return Tried::Nothing;
        }
        Tried::Found(
            re.find_iter(&self.sample)
                .filter(|m| !m.is_empty())
                .take(MAX_MATCHES)
                .map(|m| m.range())
                .collect(),
        )
    }
}

/// The sample cut at the matches: `(piece, matched)` in order.
pub fn pieces(sample: &str, found: &[Range<usize>]) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut at = 0;
    for r in found {
        if r.start > at {
            out.push((sample[at..r.start].to_owned(), false));
        }
        out.push((sample[r.clone()].to_owned(), true));
        at = r.end;
    }
    if at < sample.len() {
        out.push((sample[at..].to_owned(), false));
    }
    out
}

/// «совпадений: N», or that there is none.
pub fn count_words(n: usize) -> String {
    if n == 0 {
        "совпадений не найдено".to_owned()
    } else {
        format!("совпадений: {n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(kind: Kind) -> Builder {
        Builder {
            blocks: vec![Block::new(kind)],
            ..Builder::default()
        }
    }

    #[test]
    fn each_block_is_a_pattern_and_words() {
        let cases: Vec<(Kind, &str, &str)> = vec![
            (Kind::Text("a.b".into()), "a\\.b", "текст «a.b»"),
            (Kind::AnyChar, ".", "любой символ"),
            (
                Kind::Letter(Alphabet::Any),
                "[a-zA-Zа-яА-ЯёЁ]",
                "буква (любая)",
            ),
            (
                Kind::Letter(Alphabet::Latin),
                "[a-zA-Z]",
                "буква (латиница)",
            ),
            (
                Kind::Letter(Alphabet::Cyrillic),
                "[а-яА-ЯёЁ]",
                "буква (кириллица)",
            ),
            (Kind::Digit, "[0-9]", "цифра (0-9)"),
            (
                Kind::Number("0".into(), "20".into(), false),
                "(?:[0-9]|(?:1[0-9]|20))",
                "число от 0 до 20",
            ),
            (
                Kind::Number("5".into(), "7".into(), true),
                "(?:^|[^0-9])[5-7](?:[^0-9]|$)",
                "число от 5 до 7, отдельное — рядом нет других цифр",
            ),
            (
                Kind::OneOf("a-]".into()),
                "[a\\-\\]]",
                "один из символов: a-]",
            ),
            (
                Kind::NoneOf("^&".into()),
                "[^\\^\\&]",
                "любой символ, кроме: ^&",
            ),
            (Kind::Space, "\\s", "пробел, таб или перенос строки"),
            (Kind::WordChar, "\\w", "буква, цифра или подчёркивание"),
            (Kind::LineStart, "^", "начало текста"),
            (Kind::LineEnd, "$", "конец текста"),
            (Kind::WordBoundary, "\\b", "граница слова"),
        ];
        for (kind, pattern, words) in cases {
            let b = one(kind.clone());
            assert_eq!(b.pattern(), pattern, "{kind:?}");
            assert_eq!(b.explain(), [words], "{kind:?}");
            assert!(regex::Regex::new(&b.pattern()).is_ok(), "{kind:?}");
        }
        // Every palette button makes a block of its own kind.
        for (_, tags) in PALETTE {
            for tag in tags.iter() {
                assert_eq!(tag.block().tag(), *tag);
                assert!(!tag.name().is_empty());
            }
        }
    }

    #[test]
    fn a_range_matches_exactly_its_numbers() {
        for (from, to) in [
            (0, 20),
            (7, 7),
            (5, 123),
            (99, 1001),
            (250, 31),
            (0, 0),
            (10, 19),
        ] {
            let re = regex::Regex::new(&format!("^(?:{})$", range_pattern(from, to))).unwrap();
            let (lo, hi) = (from.min(to), from.max(to));
            for n in 0..1500u64 {
                assert_eq!(
                    re.is_match(&n.to_string()),
                    (lo..=hi).contains(&n),
                    "{from}-{to}: {n}"
                );
            }
        }
        assert_eq!(range_pattern(0, 20), "(?:[0-9]|(?:1[0-9]|20))");
    }

    #[test]
    fn quantifiers_are_written_and_said() {
        let mut b = one(Kind::Text("ab".into()));
        let cases = [
            (Times::One, false, "ab", "текст «ab»"),
            (
                Times::Optional,
                false,
                "(?:ab)?",
                "текст «ab» (необязательно, 0 или 1 раз)",
            ),
            (
                Times::Any,
                false,
                "(?:ab)*",
                "текст «ab» (0 или больше раз)",
            ),
            (
                Times::Some,
                true,
                "(?:ab)+?",
                "текст «ab» (1 или больше раз, как можно меньше)",
            ),
            (
                Times::Exactly,
                false,
                "(?:ab){2}",
                "текст «ab» (ровно 2 раза)",
            ),
            (
                Times::Between,
                false,
                "(?:ab){2,5}",
                "текст «ab» (от 2 до 5 раз)",
            ),
            (
                Times::AtLeast,
                false,
                "(?:ab){2,}",
                "текст «ab» (2 раза и больше)",
            ),
        ];
        for (times, lazy, pattern, words) in cases {
            b.blocks[0].times = times;
            b.blocks[0].lazy = lazy;
            b.blocks[0].n = "2".into();
            b.blocks[0].m = "5".into();
            assert_eq!(b.pattern(), pattern);
            assert_eq!(b.explain(), [words]);
        }
        // One character needs no group; a position takes no repetition.
        let mut d = one(Kind::Digit);
        d.blocks[0].times = Times::Exactly;
        d.blocks[0].n = "4".into();
        assert_eq!(d.pattern(), "[0-9]{4}");
        assert_eq!(d.explain(), ["цифра (0-9) (ровно 4 раза)"]);
        let mut p = one(Kind::LineStart);
        p.blocks[0].times = Times::Some;
        assert_eq!(p.pattern(), "^");
        assert_eq!(times_word(11), "раз");
        assert_eq!(times_word(22), "раза");
    }

    #[test]
    fn blocks_are_added_moved_removed_and_flagged() {
        let mut b = Builder::default();
        assert_eq!(b.pattern(), "");
        b.add(Tag::Text);
        b.add(Tag::Digit);
        b.blocks[0].kind = Kind::Text("id ".into());
        b.blocks[1].times = Times::Some;
        assert_eq!(b.pattern(), "id [0-9]+");
        b.shift(1, -1);
        assert_eq!(b.pattern(), "[0-9]+id ");
        b.shift(0, -1);
        b.shift(1, 1);
        assert_eq!(b.pattern(), "[0-9]+id ");
        b.remove(0);
        b.remove(5);
        assert_eq!(b.pattern(), "id ");
        b.any_case = true;
        b.dot_all = true;
        assert_eq!(b.pattern(), "(?is)id ");
        assert_eq!(b.flags_words().len(), 2);
    }

    #[test]
    fn the_live_test_finds_the_matches() {
        let mut b = Builder::default();
        assert_eq!(b.try_it(), Tried::Nothing);
        b.add(Tag::Text);
        b.add(Tag::Number);
        b.blocks[0].kind = Kind::Text("порт ".into());
        b.blocks[1].kind = Kind::Number("1".into(), "1024".into(), true);
        assert_eq!(b.try_it(), Tried::Nothing, "no text yet");
        b.sample = "порт 22, порт 8080, порт 443x".into();
        let Tried::Found(found) = b.try_it() else {
            panic!("{:?}", b.try_it())
        };
        let texts: Vec<&str> = found.iter().map(|r| &b.sample[r.clone()]).collect();
        // 8080 is out of range, and 22 is not taken as a part of 2222.
        assert_eq!(texts, ["порт 22,", "порт 443x"]);
        let p = pieces(&b.sample, &found);
        assert_eq!(
            p.iter().map(|(t, _)| t.as_str()).collect::<String>(),
            b.sample
        );
        assert_eq!(p.iter().filter(|(_, m)| *m).count(), 2);
        assert_eq!(count_words(2), "совпадений: 2");
        assert_eq!(count_words(0), "совпадений не найдено");
        // Typed so that it does not compile: said, not panicked.
        let mut broken = one(Kind::Digit);
        broken.blocks[0].kind = Kind::AnyChar;
        broken.blocks[0].times = Times::Between;
        broken.blocks[0].m = "1000000".into();
        broken.sample = "1".into();
        assert!(matches!(broken.try_it(), Tried::Broken(_)));
        // Any case.
        let mut c = one(Kind::Text("Abc".into()));
        c.sample = "aBC abc".into();
        assert_eq!(c.try_it(), Tried::Found(vec![]));
        c.any_case = true;
        assert_eq!(c.try_it(), Tried::Found(vec![0..3, 4..7]));
    }
}
