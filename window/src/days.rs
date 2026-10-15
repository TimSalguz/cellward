//! Days and hours in the person's local time, for the history window: the
//! date between days of the feed, a copy's hour, and a date filter's
//! bounds. The C library's `localtime_r` and `mktime` do it with the
//! system's zone database, daylight saving included — no crate, no network.

/// A moment's local calendar fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    pub year: i32,
    /// 1-12.
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
}

fn tm_of(ms: i64) -> libc::tm {
    let secs: libc::time_t = ms.div_euclid(1000) as libc::time_t;
    // SAFETY: an all-zero tm is a valid value to be overwritten.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are to locals of the right types; localtime_r
    // is the reentrant one (the window has threads).
    unsafe { libc::localtime_r(&secs, &mut tm) };
    tm
}

/// `ms` (since the epoch) in local time.
pub fn local(ms: i64) -> Local {
    let tm = tm_of(ms);
    Local {
        year: tm.tm_year + 1900,
        month: (tm.tm_mon + 1) as u32,
        day: tm.tm_mday as u32,
        hour: tm.tm_hour as u32,
        minute: tm.tm_min as u32,
    }
}

/// The moment of a local date and time, in ms; out-of-range fields roll
/// over as `mktime` rolls them (day 0 is the last of the month before).
pub fn at(year: i32, month: u32, day: i32, hour: u32, minute: u32) -> i64 {
    // SAFETY: as in `tm_of`.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month as i32 - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour as i32;
    tm.tm_min = minute as i32;
    // The zone knows whether saving time was on then.
    tm.tm_isdst = -1;
    // SAFETY: a tm of ours.
    let secs = unsafe { libc::mktime(&mut tm) };
    secs as i64 * 1000
}

/// The local midnight that starts the day of `ms`.
pub fn day_start(ms: i64) -> i64 {
    let l = local(ms);
    at(l.year, l.month, l.day as i32, 0, 0)
}

/// The day `days` after the one of `ms` (before, when negative), at its
/// local midnight — a day is not always 24 hours.
pub fn day_shift(ms: i64, days: i32) -> i64 {
    let l = local(ms);
    at(l.year, l.month, l.day as i32 + days, 0, 0)
}

const MONTHS: [&str; 12] = [
    "января",
    "февраля",
    "марта",
    "апреля",
    "мая",
    "июня",
    "июля",
    "августа",
    "сентября",
    "октября",
    "ноября",
    "декабря",
];

/// The date between days of the feed: «Сегодня», «Вчера», «12 октября»,
/// with the year when it is not this one.
pub fn day_label(ms: i64, now: i64) -> String {
    let today = day_start(now);
    let day = day_start(ms);
    if day == today {
        return "Сегодня".to_owned();
    }
    if day == day_shift(now, -1) {
        return "Вчера".to_owned();
    }
    let l = local(ms);
    let month = MONTHS[(l.month as usize - 1).min(11)];
    if l.year == local(now).year {
        format!("{} {month}", l.day)
    } else {
        format!("{} {month} {}", l.day, l.year)
    }
}

/// «14:05».
pub fn hour_label(ms: i64) -> String {
    let l = local(ms);
    format!("{:02}:{:02}", l.hour, l.minute)
}

/// When, said short, relative to now: «14:05» today, «вчера в 14:05»,
/// «12 октября в 14:05».
pub fn when_label(ms: i64, now: i64) -> String {
    let day = day_label(ms, now);
    match day.as_str() {
        "Сегодня" => hour_label(ms),
        "Вчера" => format!("вчера в {}", hour_label(ms)),
        _ => format!("{day} в {}", hour_label(ms)),
    }
}

/// A date as typed: `ДД.ММ`, `ДД.ММ.ГГГГ` (or `ГГ`), with `ЧЧ:ММ` after a
/// space if `with_time`; the year left out is the one of `now`. The local
/// moment, or `None`.
pub fn parse_date(text: &str, now: i64, with_time: bool) -> Option<i64> {
    let mut words = text.split_whitespace();
    let date = words.next()?;
    let time = words.next();
    if words.next().is_some() {
        return None;
    }
    let parts: Vec<&str> = date.split(['.', '/']).collect();
    let (day, month, year) = match parts.as_slice() {
        [d, m] => (d.parse().ok()?, m.parse().ok()?, local(now).year),
        [d, m, y] => {
            let y: i32 = y.parse().ok()?;
            (
                d.parse().ok()?,
                m.parse().ok()?,
                if y < 100 { 2000 + y } else { y },
            )
        }
        _ => return None,
    };
    let (hour, minute) = match time {
        Some(t) if with_time => {
            let (h, m) = t.split_once(':').unwrap_or((t, "0"));
            (h.parse().ok()?, m.parse().ok()?)
        }
        Some(_) => return None,
        None => (0, 0),
    };
    if !(1..=31).contains(&day) || !(1..=12).contains(&month) || hour > 23 || minute > 59 {
        return None;
    }
    let ms = at(year, month, day as i32, hour, minute);
    // 31.02 rolls over into March: not a date.
    (local(ms).day == day && local(ms).month == month).then_some(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-12 12:00 UTC: the 12th in every zone within ±11 hours.
    const OCT_12: i64 = 1_791_806_400_000;

    #[test]
    fn days_are_said_as_people_say_them() {
        let now = OCT_12 + 3 * 86_400_000;
        assert_eq!(day_label(now, now), "Сегодня");
        assert_eq!(day_label(day_start(now), now), "Сегодня");
        assert_eq!(day_label(day_start(now) - 1, now), "Вчера");
        assert_eq!(day_label(day_shift(now, -1) + 1000, now), "Вчера");
        assert_eq!(day_label(OCT_12, now), "12 октября");
        assert_eq!(day_label(OCT_12 - 365 * 86_400_000, now), "12 октября 2025");
        assert_eq!(local(OCT_12).month, 10);
        assert!(when_label(day_start(now) - 60_000, now).starts_with("вчера в "));
        assert_eq!(hour_label(at(2026, 10, 12, 9, 5)), "09:05");
    }

    #[test]
    fn a_day_starts_at_local_midnight() {
        let start = day_start(OCT_12);
        let l = local(start);
        assert_eq!((l.day, l.hour, l.minute), (12, 0, 0));
        assert_eq!(day_shift(OCT_12, 1), day_start(OCT_12 + 86_400_000));
        assert_eq!(local(day_shift(OCT_12, -12)).month, 9);
    }

    #[test]
    fn dates_are_read_as_typed() {
        let now = OCT_12;
        assert_eq!(
            parse_date("12.10", now, false),
            Some(at(2026, 10, 12, 0, 0))
        );
        assert_eq!(parse_date("1.2.25", now, false), Some(at(2025, 2, 1, 0, 0)));
        assert_eq!(
            parse_date("12.10.2026 14:30", now, true),
            Some(at(2026, 10, 12, 14, 30))
        );
        assert_eq!(parse_date("12.10.2026 14:30", now, false), None);
        assert_eq!(parse_date("31.02", now, false), None);
        assert_eq!(parse_date("вчера", now, false), None);
        assert_eq!(parse_date("", now, false), None);
    }
}
