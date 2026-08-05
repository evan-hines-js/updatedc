//! UTC rollout windows: day schedules plus time-of-day ranges during which an
//! [`UpdateGroupSet`](crate::UpdateGroupSet) is allowed to admit new rollouts.
//!
//! A set with no windows is always open (unchanged pre-window behaviour). With one or
//! more windows the set is open only while "now" (UTC) falls inside at least one of them;
//! outside every window it freezes and admits nothing new. Freezing withholds only *new*
//! admissions — a member already rolling keeps settling.
//!
//! Everything here is pure and evaluated against a caller-supplied `now`, so the schedule
//! logic — including the tricky biweekly ("every other Sunday") phase — is deterministic
//! and unit-testable without touching the clock.

use chrono::{DateTime, Datelike, Duration, NaiveDate, Timelike, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A day of the week, UTC. Named in full so the CRD reads naturally (`weekdays: [sunday]`).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl From<chrono::Weekday> for Weekday {
    fn from(value: chrono::Weekday) -> Self {
        match value {
            chrono::Weekday::Mon => Self::Monday,
            chrono::Weekday::Tue => Self::Tuesday,
            chrono::Weekday::Wed => Self::Wednesday,
            chrono::Weekday::Thu => Self::Thursday,
            chrono::Weekday::Fri => Self::Friday,
            chrono::Weekday::Sat => Self::Saturday,
            chrono::Weekday::Sun => Self::Sunday,
        }
    }
}

/// One UTC window during which rollouts may proceed. A set is open when *any* of its
/// windows is active; the pieces of a single window are ANDed — an active window is one
/// whose day rule matches the calendar day and whose time-of-day span contains the moment.
///
/// Day rule (evaluated per UTC date):
/// - Empty `weekdays` **and** empty `dates`: every day (a pure daily maintenance window).
/// - Otherwise the day matches if it is one of `dates`, or its weekday is in `weekdays`
///   and passes the `intervalWeeks` phase.
///
/// Time-of-day span: `[start, end)` in UTC `HH:MM`. Defaults span the whole day
/// (`00:00`–`24:00`). If `end <= start` the span wraps past midnight into the following
/// day (so `22:00`–`02:00` is active from 22:00 on an "on" day through 02:00 the next).
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RolloutWindow {
    /// Weekdays (UTC) the window recurs on, e.g. `[sunday]`. Empty (with empty `dates`)
    /// means every day.
    #[serde(default)]
    pub weekdays: Vec<Weekday>,
    /// Recur only every Nth week. With `weekdays: [sunday]` and `intervalWeeks: 2` this is
    /// "every other Sunday". Omitted or `1` means weekly. Requires `anchorWeek` when > 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_weeks: Option<u32>,
    /// UTC date (`YYYY-MM-DD`) whose ISO-week is an "on" week, anchoring the `intervalWeeks`
    /// phase. Any day within the intended on-week works. Required when `intervalWeeks > 1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_week: Option<String>,
    /// Specific UTC calendar dates (`YYYY-MM-DD`) the window is active on, unioned with the
    /// weekday rule.
    #[serde(default)]
    pub dates: Vec<String>,
    /// Daily span start, UTC `HH:MM`, inclusive. Default `00:00`.
    #[serde(default = "default_start")]
    pub start: String,
    /// Daily span end, UTC `HH:MM`, exclusive. Default `24:00`. `end <= start` wraps past
    /// midnight.
    #[serde(default = "default_end")]
    pub end: String,
}

fn default_start() -> String {
    "00:00".into()
}

fn default_end() -> String {
    "24:00".into()
}

/// A window's `Default` spans the whole day, matching the serde field defaults — so
/// `RolloutWindow { weekdays: vec![Weekday::Sunday], ..Default::default() }` reads as a
/// full-day Sunday window rather than the empty-string span a derived `Default` would give.
impl Default for RolloutWindow {
    fn default() -> Self {
        Self {
            weekdays: Vec::new(),
            interval_weeks: None,
            anchor_week: None,
            dates: Vec::new(),
            start: default_start(),
            end: default_end(),
        }
    }
}

/// Whether a set with these `windows` may admit new rollouts at `now` (UTC). No windows =
/// always open, preserving pre-window behaviour.
pub fn is_open(windows: &[RolloutWindow], now: DateTime<Utc>) -> bool {
    windows.is_empty() || windows.iter().any(|window| window.is_active(now))
}

/// One absolute, one-off dated window: a specific UTC calendar date with a time-of-day
/// span, e.g. `{ date: "2026-08-25", start: "06:00", end: "09:00" }`. Unlike a
/// [`RolloutWindow`] (which recurs forever), a calendar entry names a single day and
/// therefore *expires*. Dated entries do not wrap past midnight — write two entries for
/// that — so `end` must be after `start`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEntry {
    /// UTC calendar date, `YYYY-MM-DD`.
    pub date: String,
    /// Start of the allowed span on `date`, UTC `HH:MM`, inclusive. Default `00:00`.
    #[serde(default = "default_start")]
    pub start: String,
    /// End of the allowed span on `date`, UTC `HH:MM`, exclusive. Default `24:00`. Must be
    /// after `start`.
    #[serde(default = "default_end")]
    pub end: String,
}

impl CalendarEntry {
    /// The entry's absolute `[start, end)` instant span, or `None` if any field is
    /// unparseable or `end <= start` (a misconfiguration `validate` surfaces).
    fn span(&self) -> Option<(chrono::NaiveDateTime, chrono::NaiveDateTime)> {
        let date = parse_date(&self.date)?;
        let start = parse_minute(&self.start)?;
        let end = parse_minute(&self.end)?;
        if end <= start {
            return None;
        }
        let midnight = date.and_hms_opt(0, 0, 0)?;
        Some((
            midnight + Duration::minutes(start as i64),
            midnight + Duration::minutes(end as i64),
        ))
    }

    /// Reject an entry whose fields cannot be honoured (bad date/time, or `end <= start`).
    pub fn validate(&self) -> Result<(), String> {
        if parse_date(&self.date).is_none() {
            return Err(format!("date {:?} is not a UTC YYYY-MM-DD date", self.date));
        }
        let start = parse_minute(&self.start)
            .ok_or_else(|| format!("start {:?} is not a UTC HH:MM time", self.start))?;
        let end = parse_minute(&self.end)
            .ok_or_else(|| format!("end {:?} is not a UTC HH:MM time", self.end))?;
        if end <= start {
            return Err(format!(
                "end {:?} must be after start {:?} (dated entries do not wrap past midnight)",
                self.end, self.start
            ));
        }
        Ok(())
    }
}

/// Whether a `calendar` of dated entries admits rollouts at `now` (UTC).
///
/// - No entries at all → open: the set declares no calendar, so the calendar does not gate.
/// - `now` falls inside one usable entry's span → open.
/// - The calendar has [run out](ran_out) → open. This is the "runs out, falls back" rule: once
///   the whole calendar has expired it stops gating, so a stale calendar never wedges the set.
/// - Otherwise (entries remain in the future, none active now) → closed: the set waits,
///   frozen, for its next approved window.
///
/// A calendar that was WRITTEN but yields no usable span therefore fails CLOSED, the same
/// direction [`RolloutWindow::is_active`] fails: an entry nobody can evaluate is not permission
/// to roll at every instant. The set reports it as `frozen`, and `validate` names the entry.
pub fn calendar_open(calendar: &[CalendarEntry], now: DateTime<Utc>) -> bool {
    if calendar.is_empty() {
        return true;
    }
    let spans = usable_spans(calendar);
    let instant = now.naive_utc();
    spans
        .iter()
        .any(|(start, end)| *start <= instant && instant < *end)
        || ran_out(calendar, &spans, instant)
}

/// Whether a `calendar` that *had* dated entries has now run out — it has at least one entry,
/// every entry is usable, and every one of them is in the past. This is the moment
/// [`calendar_open`] flips from gating to always-open (fail-open): the set silently stops being
/// approval-gated.
///
/// Requiring EVERY entry to be usable is what keeps the fail-open rule honest. An entry that
/// cannot be parsed is not a window in the past — it is a gate the operator wrote and this code
/// cannot evaluate — so a calendar holding one keeps gating rather than quietly becoming ungated
/// at every hour. An entirely unusable calendar is never "exhausted" either, so it stays closed
/// instead of opening.
fn ran_out(
    calendar: &[CalendarEntry],
    spans: &[(chrono::NaiveDateTime, chrono::NaiveDateTime)],
    now: chrono::NaiveDateTime,
) -> bool {
    spans.len() == calendar.len() && !spans.is_empty() && spans.iter().all(|(_, end)| now >= *end)
}

fn usable_spans(calendar: &[CalendarEntry]) -> Vec<(chrono::NaiveDateTime, chrono::NaiveDateTime)> {
    calendar.iter().filter_map(CalendarEntry::span).collect()
}

/// Whether `calendar` has [run out](ran_out), for the status field that tells an operator their
/// approval window expired and this set is now ungated at any hour. The single predicate
/// [`calendar_open`] opens on, so status and gate can never disagree about it.
pub fn calendar_exhausted(calendar: &[CalendarEntry], now: DateTime<Utc>) -> bool {
    ran_out(calendar, &usable_spans(calendar), now.naive_utc())
}

impl RolloutWindow {
    /// Whether this window is active (rollouts allowed) at `now` (UTC).
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        let (Some(start), Some(end)) = (parse_minute(&self.start), parse_minute(&self.end)) else {
            // A window we can't parse never opens (fail-safe: keep rollouts frozen rather
            // than roll on a misread schedule). `validate` surfaces the misconfiguration.
            return false;
        };
        let today = now.date_naive();
        let minute = now.hour() * 60 + now.minute();
        if start < end {
            // Same-day span: the moment's day itself must be an active day.
            self.is_active_day(today) && (start..end).contains(&minute)
        } else {
            // Wraps past midnight: [start, 24:00) belongs to today as an on-day; [0, end)
            // belongs to the day *after* an on-day. start == end means the whole day.
            if start == end {
                return self.is_active_day(today);
            }
            (minute >= start && self.is_active_day(today))
                || (minute < end
                    && today
                        .checked_sub_signed(Duration::days(1))
                        .is_some_and(|yesterday| self.is_active_day(yesterday)))
        }
    }

    /// Whether `date` (UTC) is one this window's day rule selects, ignoring time of day.
    fn is_active_day(&self, date: NaiveDate) -> bool {
        // Explicit dates are a straight union with the weekday rule.
        if self
            .dates
            .iter()
            .filter_map(|raw| parse_date(raw))
            .any(|listed| listed == date)
        {
            return true;
        }
        if self.weekdays.is_empty() {
            // Empty weekdays means "every day" only when no dates narrowed the window;
            // otherwise the window is date-list-only and this date was not in it.
            return self.dates.is_empty();
        }
        if !self.weekdays.contains(&date.weekday().into()) {
            return false;
        }
        match self.interval_weeks {
            None | Some(0) | Some(1) => true,
            Some(interval) => match self.anchor_week.as_deref().and_then(parse_date) {
                // N-weekly with no valid anchor never opens (fail-safe; caught by `validate`).
                None => false,
                Some(anchor) => weeks_between(anchor, date)
                    .is_some_and(|weeks| weeks.rem_euclid(interval as i64) == 0),
            },
        }
    }

    /// Reject a window whose fields cannot be honoured. Reconcile logs these; an invalid
    /// window still fails safe (never opens) so a typo freezes rollouts rather than
    /// silently rolling on a schedule the operator did not mean.
    pub fn validate(&self) -> Result<(), String> {
        if parse_minute(&self.start).is_none() {
            return Err(format!("start {:?} is not a UTC HH:MM time", self.start));
        }
        if parse_minute(&self.end).is_none() {
            return Err(format!("end {:?} is not a UTC HH:MM time", self.end));
        }
        for raw in &self.dates {
            if parse_date(raw).is_none() {
                return Err(format!("date {raw:?} is not a UTC YYYY-MM-DD date"));
            }
        }
        if matches!(self.interval_weeks, Some(n) if n > 1) {
            match self.anchor_week.as_deref() {
                None => return Err("intervalWeeks > 1 requires anchorWeek".into()),
                Some(raw) => match parse_date(raw) {
                    None => {
                        return Err(format!("anchorWeek {raw:?} is not a UTC YYYY-MM-DD date"));
                    }
                    // The interval is counted from the anchor's Monday, which does not exist for a
                    // date within six days of the start of the representable range.
                    Some(anchor) if monday_of_week(anchor).is_none() => {
                        return Err(format!("anchorWeek {raw:?} is not in a representable week"));
                    }
                    Some(_) => {}
                },
            }
        }
        Ok(())
    }
}

/// Whole weeks from `anchor`'s week to `date`'s week (Monday-based), signed. Both operands
/// are normalised to their week's Monday first, so the difference is always a multiple of 7
/// and the parity holds regardless of which weekday the anchor was given as, or which side
/// of the anchor `date` falls on.
///
/// `None` when either week's Monday falls outside the representable date range — an anchor within
/// six days of `NaiveDate::MIN`. The arithmetic panics rather than saturating, and this is
/// evaluated on the reconcile task for every set on every pass, so it is checked here and the
/// window fails closed like any other schedule it cannot evaluate. `validate` rejects such an
/// anchor so the operator sees why.
fn weeks_between(anchor: NaiveDate, date: NaiveDate) -> Option<i64> {
    Some((monday_of_week(date)? - monday_of_week(anchor)?).num_days() / 7)
}

fn monday_of_week(date: NaiveDate) -> Option<NaiveDate> {
    date.checked_sub_signed(Duration::days(date.weekday().num_days_from_monday() as i64))
}

/// Parse `HH:MM` into minutes-since-midnight (`0..=1440`). `24:00` is the end-of-day
/// sentinel used by the default span.
fn parse_minute(raw: &str) -> Option<u32> {
    let (hh, mm) = raw.split_once(':')?;
    let hours: u32 = hh.parse().ok()?;
    let minutes: u32 = mm.parse().ok()?;
    if minutes >= 60 || hours > 24 || (hours == 24 && minutes != 0) {
        return None;
    }
    Some(hours * 60 + minutes)
}

fn parse_date(raw: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn window() -> RolloutWindow {
        RolloutWindow {
            start: default_start(),
            end: default_end(),
            ..Default::default()
        }
    }

    #[test]
    fn no_windows_is_always_open() {
        assert!(is_open(&[], at("2026-07-20T12:00:00Z")));
    }

    #[test]
    fn every_sunday_all_day() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            ..window()
        };
        // 2026-07-19 is a Sunday; 2026-07-20 is a Monday.
        assert!(w.is_active(at("2026-07-19T00:00:00Z")));
        assert!(w.is_active(at("2026-07-19T23:59:00Z")));
        assert!(!w.is_active(at("2026-07-20T12:00:00Z")));
    }

    #[test]
    fn weekday_window_respects_time_span() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            start: "02:00".into(),
            end: "04:00".into(),
            ..window()
        };
        assert!(!w.is_active(at("2026-07-19T01:59:00Z")));
        assert!(w.is_active(at("2026-07-19T02:00:00Z")));
        assert!(w.is_active(at("2026-07-19T03:59:00Z")));
        assert!(!w.is_active(at("2026-07-19T04:00:00Z")));
    }

    #[test]
    fn every_other_sunday_holds_the_biweekly_phase() {
        // Anchor in the week of Sunday 2026-07-19 (anchor given as a weekday mid-week to
        // prove normalisation). intervalWeeks 2 => that Sunday and every second one after.
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            interval_weeks: Some(2),
            anchor_week: Some("2026-07-15".into()), // Wednesday in the on-week
            ..window()
        };
        assert!(
            w.is_active(at("2026-07-19T12:00:00Z")),
            "anchor Sunday is on"
        );
        assert!(
            !w.is_active(at("2026-07-26T12:00:00Z")),
            "next Sunday is off"
        );
        assert!(
            w.is_active(at("2026-08-02T12:00:00Z")),
            "two weeks later is on"
        );
        assert!(!w.is_active(at("2026-08-09T12:00:00Z")), "odd week is off");
        // Parity holds symmetrically before the anchor, too.
        assert!(
            w.is_active(at("2026-07-05T12:00:00Z")),
            "two weeks before is on"
        );
        assert!(
            !w.is_active(at("2026-07-12T12:00:00Z")),
            "one week before is off"
        );
    }

    #[test]
    fn every_third_week_also_works() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            interval_weeks: Some(3),
            anchor_week: Some("2026-07-19".into()),
            ..window()
        };
        assert!(w.is_active(at("2026-07-19T12:00:00Z")));
        assert!(!w.is_active(at("2026-07-26T12:00:00Z")));
        assert!(!w.is_active(at("2026-08-02T12:00:00Z")));
        assert!(w.is_active(at("2026-08-09T12:00:00Z")));
    }

    #[test]
    fn past_midnight_span_wraps_into_the_next_day() {
        // Active Saturday 22:00 UTC through Sunday 02:00 UTC.
        let w = RolloutWindow {
            weekdays: vec![Weekday::Saturday],
            start: "22:00".into(),
            end: "02:00".into(),
            ..window()
        };
        // 2026-07-18 is a Saturday, 2026-07-19 a Sunday.
        assert!(!w.is_active(at("2026-07-18T21:59:00Z")));
        assert!(w.is_active(at("2026-07-18T22:30:00Z")), "Saturday evening");
        assert!(
            w.is_active(at("2026-07-19T01:30:00Z")),
            "spills into Sunday morning"
        );
        assert!(!w.is_active(at("2026-07-19T02:00:00Z")), "span closed");
        assert!(
            !w.is_active(at("2026-07-19T12:00:00Z")),
            "Sunday midday is not its own on-day"
        );
    }

    #[test]
    fn explicit_dates_union_with_weekdays() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            dates: vec!["2026-07-20".into()], // a Monday
            ..window()
        };
        assert!(
            w.is_active(at("2026-07-19T12:00:00Z")),
            "Sunday via weekday rule"
        );
        assert!(
            w.is_active(at("2026-07-20T12:00:00Z")),
            "Monday via explicit date"
        );
        assert!(!w.is_active(at("2026-07-21T12:00:00Z")), "Tuesday: neither");
    }

    #[test]
    fn date_only_window_does_not_match_every_day() {
        let w = RolloutWindow {
            dates: vec!["2026-12-25".into()],
            ..window()
        };
        assert!(w.is_active(at("2026-12-25T12:00:00Z")));
        assert!(!w.is_active(at("2026-12-26T12:00:00Z")));
    }

    #[test]
    fn empty_schedule_is_a_daily_window() {
        let w = RolloutWindow {
            start: "01:00".into(),
            end: "03:00".into(),
            ..window()
        };
        assert!(w.is_active(at("2026-07-19T02:00:00Z")), "Sunday");
        assert!(w.is_active(at("2026-07-22T02:00:00Z")), "Wednesday");
        assert!(
            !w.is_active(at("2026-07-22T04:00:00Z")),
            "outside the daily span"
        );
    }

    #[test]
    fn union_of_windows_opens_the_set() {
        let sunday = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            ..window()
        };
        let wednesday_night = RolloutWindow {
            weekdays: vec![Weekday::Wednesday],
            start: "22:00".into(),
            end: "23:00".into(),
            ..window()
        };
        let windows = [sunday, wednesday_night];
        assert!(
            is_open(&windows, at("2026-07-19T12:00:00Z")),
            "Sunday window"
        );
        assert!(
            is_open(&windows, at("2026-07-22T22:30:00Z")),
            "Wednesday window"
        );
        assert!(
            !is_open(&windows, at("2026-07-21T12:00:00Z")),
            "Tuesday: closed"
        );
    }

    #[test]
    fn unparseable_window_fails_safe_closed() {
        let w = RolloutWindow {
            start: "9am".into(),
            ..window()
        };
        assert!(!w.is_active(at("2026-07-19T09:30:00Z")));
        assert!(w.validate().is_err());
    }

    #[test]
    fn n_weekly_without_anchor_is_rejected_and_never_opens() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            interval_weeks: Some(2),
            ..window()
        };
        assert!(w.validate().is_err());
        assert!(!w.is_active(at("2026-07-19T12:00:00Z")));
    }

    #[test]
    fn an_anchor_with_no_representable_week_is_rejected_and_never_opens() {
        // Normalising a date to its week's Monday PANICS below `NaiveDate::MIN + 6 days` rather
        // than saturating, and `is_active` runs on the reconcile task for every set on every pass:
        // the panic killed the controller, which restarted, re-read the same UpdateGroupSet and
        // died again, stopping publication for the whole repository.
        let w = RolloutWindow {
            weekdays: every_weekday(),
            interval_weeks: Some(2),
            anchor_week: Some("-262143-01-01".into()),
            ..window()
        };
        assert!(w.validate().is_err());
        assert!(!w.is_active(at("2026-07-19T12:00:00Z")));
        // Six days later the week IS representable, so the ordinary rule applies and nothing is
        // rejected — the bound is exactly where the arithmetic stops working.
        let usable = RolloutWindow {
            anchor_week: Some("-262143-01-05".into()),
            ..w
        };
        assert!(usable.validate().is_ok());
    }

    fn every_weekday() -> Vec<Weekday> {
        vec![
            Weekday::Monday,
            Weekday::Tuesday,
            Weekday::Wednesday,
            Weekday::Thursday,
            Weekday::Friday,
            Weekday::Saturday,
            Weekday::Sunday,
        ]
    }

    #[test]
    fn all_weekdays_all_day_never_blocks() {
        // The explicit "always" shape: every weekday, full-day span. Open at every instant
        // swept across a whole week — it never blocks a rollout.
        let w = RolloutWindow {
            weekdays: every_weekday(),
            ..window()
        };
        let base = at("2026-07-13T00:00:00Z"); // a Monday
        for hour in 0i64..(24 * 7) {
            let now = base + Duration::hours(hour);
            assert!(w.is_active(now), "should never block at {now}");
            assert!(is_open(std::slice::from_ref(&w), now));
        }
    }

    #[test]
    fn empty_schedule_daily_window_never_blocks_across_the_week() {
        // No weekdays and no dates => every day, and the default span is the full day: the
        // window is open at every hour of every day.
        let w = window();
        let base = at("2026-07-13T00:00:00Z");
        for hour in 0i64..(24 * 7) {
            assert!(w.is_active(base + Duration::hours(hour)));
        }
    }

    #[test]
    fn full_day_span_covers_first_and_last_minute() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            ..window()
        };
        assert!(w.is_active(at("2026-07-19T00:00:00Z")), "00:00 inclusive");
        assert!(
            w.is_active(at("2026-07-19T23:59:00Z")),
            "23:59 covered by the 24:00 end"
        );
    }

    #[test]
    fn equal_non_default_start_and_end_is_a_full_day() {
        // A degenerate 09:00–09:00 span is the whole on-day, never a zero-length gap that
        // would silently block for 24 hours.
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            start: "09:00".into(),
            end: "09:00".into(),
            ..window()
        };
        assert!(w.is_active(at("2026-07-19T00:00:00Z")));
        assert!(w.is_active(at("2026-07-19T23:59:00Z")));
        assert!(
            !w.is_active(at("2026-07-20T09:00:00Z")),
            "still only on its weekday"
        );
    }

    #[test]
    fn all_windows_invalid_stays_closed_without_panicking() {
        // Every window is misconfigured. The set never opens — but nothing panics, and it is
        // uniformly closed rather than flickering. `validate` flags each one for the operator.
        let windows = [
            RolloutWindow {
                start: "nope".into(),
                ..window()
            },
            RolloutWindow {
                weekdays: vec![Weekday::Sunday],
                interval_weeks: Some(2), // missing anchorWeek
                ..window()
            },
            RolloutWindow {
                dates: vec!["not-a-date".into()],
                ..window()
            },
        ];
        let base = at("2026-07-13T00:00:00Z");
        for hour in 0i64..(24 * 7) {
            assert!(!is_open(&windows, base + Duration::hours(hour)));
        }
        assert!(windows.iter().all(|w| w.validate().is_err()));
    }

    #[test]
    fn validate_accepts_the_biweekly_shape() {
        let w = RolloutWindow {
            weekdays: vec![Weekday::Sunday],
            interval_weeks: Some(2),
            anchor_week: Some("2026-07-19".into()),
            start: "02:00".into(),
            end: "04:00".into(),
            ..Default::default()
        };
        assert!(w.validate().is_ok());
    }

    // ── calendar (one-off dated windows) ──────────────────────────────────────────

    fn entry(date: &str, start: &str, end: &str) -> CalendarEntry {
        CalendarEntry {
            date: date.into(),
            start: start.into(),
            end: end.into(),
        }
    }

    #[test]
    fn empty_calendar_does_not_gate() {
        assert!(calendar_open(&[], at("2026-08-25T07:00:00Z")));
    }

    #[test]
    fn calendar_admits_only_inside_a_dated_window() {
        // "only valid August 25 2026, 06:00–09:00 UTC".
        let cal = [entry("2026-08-25", "06:00", "09:00")];
        assert!(
            !calendar_open(&cal, at("2026-08-25T05:59:00Z")),
            "before the window: frozen"
        );
        assert!(
            calendar_open(&cal, at("2026-08-25T06:00:00Z")),
            "start is inclusive"
        );
        assert!(
            calendar_open(&cal, at("2026-08-25T08:59:00Z")),
            "inside the window"
        );
        // A day before the window — same time of day — is still pending, so frozen. (A day
        // *after* the sole entry would instead be "ran out → open"; that fallback, including
        // the exclusive end boundary, is covered by the pending-entry and run-out tests.)
        assert!(
            !calendar_open(&cal, at("2026-08-24T07:00:00Z")),
            "before the window day: frozen"
        );
    }

    #[test]
    fn calendar_runs_out_and_falls_back_to_open() {
        // A single past window: once its day is over the calendar is exhausted, so it stops
        // gating entirely — the set falls back to open rather than freezing forever.
        let cal = [entry("2026-08-25", "06:00", "09:00")];
        assert!(
            calendar_open(&cal, at("2026-08-25T12:00:00Z")),
            "same day, after the window"
        );
        assert!(
            calendar_open(&cal, at("2027-01-01T00:00:00Z")),
            "long after: ran out, open"
        );
    }

    #[test]
    fn a_pending_future_entry_keeps_the_calendar_shut() {
        // Two entries, one past and one still to come. Between them the calendar has NOT run
        // out — the future window is pending — so the set stays frozen until it opens.
        let cal = [
            entry("2026-08-25", "06:00", "09:00"),
            entry("2026-09-01", "22:00", "23:30"),
        ];
        // Exactly at the first window's exclusive end, with the second still pending: frozen.
        // This is where end-exclusivity is observable (a sole entry would have run out here).
        assert!(
            !calendar_open(&cal, at("2026-08-25T09:00:00Z")),
            "first window's end is exclusive"
        );
        assert!(
            !calendar_open(&cal, at("2026-08-27T12:00:00Z")),
            "between windows: waiting"
        );
        assert!(
            calendar_open(&cal, at("2026-09-01T22:30:00Z")),
            "inside the later window"
        );
        assert!(
            calendar_open(&cal, at("2026-09-02T00:00:00Z")),
            "both past: ran out, open"
        );
    }

    #[test]
    fn a_calendar_no_entry_of_which_is_usable_fails_closed() {
        // An entry nobody can evaluate is not permission to roll at every instant. A calendar was
        // written, so it gates; none of it can be honoured, so it never opens — the direction
        // `RolloutWindow::is_active` already fails, and the set reports it as `frozen`.
        let unparseable = entry("not-a-date", "06:00", "09:00");
        // `span` also rejects end <= start, so an overnight entry is unusable the same way: this
        // one used to leave the gate wide open at every instant of every day.
        let overnight = entry("2026-08-25", "22:00", "06:00");
        for bad in [&unparseable, &overnight] {
            assert!(bad.validate().is_err());
            let calendar = std::slice::from_ref(bad);
            assert!(
                !calendar_open(calendar, at("2026-08-25T07:00:00Z")),
                "an unusable calendar never opens"
            );
            assert!(
                !calendar_exhausted(calendar, at("2030-01-01T00:00:00Z")),
                "it never gated on a date, so it can never have run out either"
            );
        }

        // One unusable entry alongside a real one keeps the calendar gating: the typo may have
        // been the operator's next approval window, so the set stays frozen past the good entry
        // instead of falling back to ungated.
        let mixed = [entry("2026-08-25", "06:00", "09:00"), unparseable.clone()];
        assert!(
            calendar_open(&mixed, at("2026-08-25T07:00:00Z")),
            "inside the usable window"
        );
        assert!(
            !calendar_open(&mixed, at("2026-08-26T07:00:00Z")),
            "past the usable window, but the calendar has not run out"
        );
        assert!(!calendar_exhausted(&mixed, at("2026-08-26T07:00:00Z")));

        // end must be after start; dated entries do not wrap past midnight.
        assert!(entry("2026-08-25", "09:00", "06:00").validate().is_err());
        assert!(entry("2026-08-25", "09:00", "09:00").validate().is_err());
        assert!(entry("2026-08-25", "06:00", "09:00").validate().is_ok());
    }
}
