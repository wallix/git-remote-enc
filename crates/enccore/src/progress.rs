//! Progress reporting for the slow steps: downloading and uploading the
//! backend branch, verifying and indexing packs. On when git asks for it
//! (`option progress true`), else when stderr is a terminal.

use std::io::{self, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const UNSET: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;

static PROGRESS: AtomicU8 = AtomicU8::new(UNSET);

/// Like git, a meter only appears once a step has run this long.
const DELAY: Duration = Duration::from_secs(1);
const INTERVAL: Duration = Duration::from_millis(200);

pub fn set_enabled(on: bool) {
    PROGRESS.store(if on { ON } else { OFF }, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    match PROGRESS.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => io::stderr().is_terminal(),
    }
}

/// `1.5 GiB`, `730.2 MiB`, `12 KiB`.
pub fn human(bytes: u64) -> String {
    const ABOVE_KIB: [&str; 3] = ["MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64 / 1024.0;
    let mut unit = "KiB";
    // Whole KiB, tenths above.
    let mut places = 0;
    for u in ABOVE_KIB {
        // Compare the value as printed: 1023.9 KiB is 1.0 MiB, not 1024 KiB.
        let scale = if places == 0 { 1.0 } else { 10.0 };
        if (v * scale).round() < 1024.0 * scale {
            break;
        }
        v /= 1024.0;
        unit = u;
        places = 1;
    }
    format!("{v:.places$} {unit}")
}

/// A byte meter in git's style: `enc: verifying pack 1/2:  37% (900.0 MiB /
/// 2.4 GiB), 150.0 MiB/s`, rewritten in place and closed with `, done.`.
pub struct Meter {
    label: String,
    total: Option<u64>,
    done: u64,
    start: Instant,
    last: Option<Instant>,
    /// Length of the line last drawn, to blank out its tail on a redraw.
    width: usize,
    on: bool,
}

impl Meter {
    pub fn new(label: impl Into<String>, total: Option<u64>) -> Self {
        Self {
            label: label.into(),
            total,
            done: 0,
            start: Instant::now(),
            last: None,
            width: 0,
            on: enabled(),
        }
    }

    pub fn add(&mut self, n: u64) {
        self.done = self.done.saturating_add(n);
        if !self.on {
            return;
        }
        let now = Instant::now();
        if now.duration_since(self.start) < DELAY {
            return;
        }
        if self.last.is_some_and(|l| now.duration_since(l) < INTERVAL) {
            return;
        }
        self.last = Some(now);
        self.print(false);
    }

    /// Closes the line if the meter was shown.
    pub fn finish(&mut self) {
        if self.on && self.last.is_some() {
            self.print(true);
            self.last = None;
        }
    }

    fn print(&mut self, done: bool) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            (self.done as f64 / elapsed) as u64
        } else {
            0
        };
        let amount = match self.total {
            Some(t) if t > 0 => {
                let pct = self
                    .done
                    .saturating_mul(100)
                    .checked_div(t)
                    .unwrap_or(0)
                    .min(100);
                format!("{pct:3}% ({} / {})", human(self.done), human(t))
            }
            _ => human(self.done),
        };
        let mut line = format!("enc: {}: {amount}, {}/s", self.label, human(rate));
        if done {
            line.push_str(", done.");
        }
        let pad = self.width.saturating_sub(line.len());
        self.width = line.len();
        let eol = if done { '\n' } else { '\r' };
        let mut err = io::stderr().lock();
        // Best effort: progress is cosmetic.
        let _ = write!(err, "{line}{:pad$}{eol}", "");
        let _ = err.flush();
    }
}

impl Drop for Meter {
    fn drop(&mut self) {
        // An interrupted step leaves the cursor on a fresh line.
        if self.on && self.last.is_some() {
            let _ = writeln!(io::stderr());
        }
    }
}

/// A reader that advances a [`Meter`].
pub struct MeterReader<R: Read> {
    inner: R,
    meter: Meter,
}

impl<R: Read> MeterReader<R> {
    pub fn new(inner: R, meter: Meter) -> Self {
        Self { inner, meter }
    }
}

impl<R: Read> Read for MeterReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter.add(n as u64);
        if n == 0 && !buf.is_empty() {
            self.meter.finish();
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(1023), "1023 B");
        assert_eq!(human(1024), "1 KiB");
        assert_eq!(human(1536), "2 KiB");
        assert_eq!(human(1_047_552), "1023 KiB");
        assert_eq!(human(1_048_575), "1.0 MiB");
        assert_eq!(human(1_048_576), "1.0 MiB");
        assert_eq!(human((1 << 30) - 1), "1.0 GiB");
        assert_eq!(human(1 << 40), "1.0 TiB");
        assert_eq!(human(u64::MAX), "16777216.0 TiB");
        assert_eq!(human(48 << 20), "48.0 MiB");
        assert_eq!(human(2_621_928_938), "2.4 GiB");
    }
}
