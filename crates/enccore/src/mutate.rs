//! Deterministic input mutation for the parser robustness tests: a small
//! stand-in for coverage-guided fuzzing, which needs a nightly toolchain the
//! pinned one does not provide. Each test feeds thousands of corrupted
//! variants of a valid input to a parser that must return, never panic.

/// xorshift64*: reproducible across runs, no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Bytes that make parsers take unusual branches.
const INTERESTING: &[u8] = b" \n\r\t\0#@:+-=/0123456789abcdefABCDEF\xff\xc3\x28";

/// `count` variants of `seed`, each with one to four random edits: bit
/// flips, byte insertions and deletions, interesting bytes, truncation,
/// duplicated or dropped lines.
pub fn variants(seed: &[u8], count: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(0x5eed ^ seed.len() as u64);
    (0..count)
        .map(|_| {
            let mut v = seed.to_vec();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut v);
            }
            v
        })
        .collect()
}

fn mutate(rng: &mut Rng, v: &mut Vec<u8>) {
    let at = rng.below(v.len().max(1));
    match rng.below(7) {
        0 if !v.is_empty() => v[at] ^= 1 << rng.below(8),
        1 => v.insert(at.min(v.len()), rng.next() as u8),
        2 if !v.is_empty() => {
            v.remove(at);
        }
        3 if !v.is_empty() => v[at] = INTERESTING[rng.below(INTERESTING.len())],
        4 => v.truncate(at),
        5 => {
            // Duplicate the line around `at`.
            let start = v[..at.min(v.len())]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            let end = v[start..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(v.len(), |i| start + i + 1);
            let line = v[start..end].to_vec();
            v.splice(end..end, line);
        }
        _ => {
            // Drop the line around `at`.
            let start = v[..at.min(v.len())]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            let end = v[start..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(v.len(), |i| start + i + 1);
            v.drain(start..end);
        }
    }
}
