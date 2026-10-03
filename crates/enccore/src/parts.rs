//! A pack blob stored as fixed-size parts: `<id>.age.0000`, `<id>.age.0001`,
//! … (at least four digits: `.9999` is followed by `.10000`), whose
//! concatenation is the age file `<id>.age` would hold. DESIGN.md §4.4.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::backend::Backend;
use crate::git::{Oid, Streaming, TreeEntry};

/// The tree name of part `n` of pack `id`.
pub fn part_name(id: &str, n: usize) -> String {
    format!("{id}.age.{n:04}")
}

/// The blobs holding pack `id`, in order: `<id>.age` alone, else its parts
/// `<id>.age.0000` up to the first gap. `None` when neither is there.
/// Whatever the host serves is checked against `id` by the reader.
pub fn find(tree: &[TreeEntry], id: &str) -> Option<Vec<Oid>> {
    let blobs: HashMap<&str, &str> = tree
        .iter()
        .filter(|(_, ty, _, _)| ty == "blob")
        .map(|(_, _, oid, name)| (name.as_str(), oid.as_str()))
        .collect();
    if let Some(oid) = blobs.get(format!("{id}.age").as_str()) {
        return Some(vec![(*oid).to_owned()]);
    }
    let parts: Vec<Oid> = (0..)
        .map_while(|n| blobs.get(part_name(id, n).as_str()).copied())
        .map(str::to_owned)
        .collect();
    (!parts.is_empty()).then_some(parts)
}

/// Writes a stream into files `<base>.part0`, `<base>.part1`, … of at most
/// `size` bytes each (0: one file).
pub struct PartWriter {
    base: PathBuf,
    size: u64,
    paths: Vec<PathBuf>,
    current: Option<std::fs::File>,
    written: u64,
}

impl PartWriter {
    pub fn new(base: &Path, size: u64) -> Self {
        Self {
            base: base.to_owned(),
            size,
            paths: Vec::new(),
            current: None,
            written: 0,
        }
    }

    /// The files written, synced to disk.
    pub fn finish(mut self) -> Result<Vec<PathBuf>> {
        if let Some(f) = self.current.take() {
            f.sync_all().context("syncing pack part")?;
        }
        Ok(std::mem::take(&mut self.paths))
    }

    /// The file being written, opening the next one when the current one is
    /// full.
    fn file(&mut self) -> io::Result<&mut std::fs::File> {
        let full = self.size > 0 && self.written >= self.size;
        if full && let Some(f) = self.current.take() {
            f.sync_all()?;
        }
        if self.current.is_none() {
            let mut name = self.base.clone().into_os_string();
            name.push(format!(".part{}", self.paths.len()));
            let path = PathBuf::from(name);
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            self.paths.push(path);
            self.written = 0;
            self.current = Some(f);
        }
        self.current
            .as_mut()
            .ok_or_else(|| io::Error::other("no part file"))
    }

    /// Best effort: remove what was written.
    pub fn discard(paths: &[PathBuf]) {
        for p in paths {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Write for PartWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let room = if self.size == 0 {
            u64::MAX
        } else {
            self.size.saturating_sub(self.written)
        };
        let room = if room == 0 { self.size } else { room };
        let take = usize::try_from(room).unwrap_or(usize::MAX).min(buf.len());
        let chunk = buf.get(..take).unwrap_or(buf);
        let n = self.file()?.write(chunk)?;
        self.written = self.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.current {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for PartWriter {
    fn drop(&mut self) {
        // Not finished: an error left them half written.
        Self::discard(&self.paths);
    }
}

/// Reads blobs of the backend repository back to back, one `git cat-file`
/// at a time; a failing `cat-file` is a read error.
pub struct BlobChain<'a> {
    backend: &'a Backend,
    oids: std::vec::IntoIter<Oid>,
    current: Option<(Streaming, std::process::ChildStdout)>,
}

impl<'a> BlobChain<'a> {
    pub fn new(backend: &'a Backend, oids: Vec<Oid>) -> Self {
        Self {
            backend,
            oids: oids.into_iter(),
            current: None,
        }
    }

    fn open_next(&mut self) -> Result<bool> {
        let Some(oid) = self.oids.next() else {
            return Ok(false);
        };
        let mut cat = self.backend.blob_reader(&oid)?;
        let out = cat.stdout()?;
        self.current = Some((cat, out));
        Ok(true)
    }
}

impl Read for BlobChain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.current.is_none() && !self.open_next().map_err(io::Error::other)? {
                return Ok(0);
            }
            let Some((_, out)) = &mut self.current else {
                return Ok(0);
            };
            let n = out.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if let Some((cat, _)) = self.current.take() {
                cat.finish().map_err(io::Error::other)?;
            }
        }
    }
}

/// Total size of the backend blobs `oids`.
pub fn total_size(backend: &Backend, oids: &[Oid]) -> Result<u64> {
    oids.iter().try_fold(0u64, |acc, oid| {
        acc.checked_add(backend.object_size(oid)?)
            .ok_or_else(|| anyhow!("pack size overflow"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("enc-parts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn writer_cuts_at_the_part_size() {
        let d = tmpdir("cut");
        let mut w = PartWriter::new(&d.join("pack"), 10);
        let data: Vec<u8> = (0..=24).collect();
        w.write_all(&data[..7]).unwrap();
        w.write_all(&data[7..]).unwrap();
        let paths = w.finish().unwrap();
        let lens: Vec<u64> = paths
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .collect();
        assert_eq!(lens, [10, 10, 5]);
        let joined: Vec<u8> = paths
            .iter()
            .flat_map(|p| std::fs::read(p).unwrap())
            .collect();
        assert_eq!(joined, data);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_exact_multiple_leaves_no_empty_part() {
        let d = tmpdir("exact");
        let mut w = PartWriter::new(&d.join("pack"), 4);
        w.write_all(&[1; 8]).unwrap();
        let paths = w.finish().unwrap();
        assert_eq!(paths.len(), 2);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn size_zero_writes_one_file() {
        let d = tmpdir("whole");
        let mut w = PartWriter::new(&d.join("pack"), 0);
        w.write_all(&[1; 100_000]).unwrap();
        assert_eq!(w.finish().unwrap().len(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_unfinished_writer_removes_its_files() {
        let d = tmpdir("drop");
        {
            let mut w = PartWriter::new(&d.join("pack"), 4);
            w.write_all(&[1; 10]).unwrap();
        }
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn part_names_grow_past_four_digits() {
        assert_eq!(part_name("aa", 0), "aa.age.0000");
        assert_eq!(part_name("aa", 9999), "aa.age.9999");
        assert_eq!(part_name("aa", 10_000), "aa.age.10000");
        let e = |n: usize| -> TreeEntry {
            (
                "100644".into(),
                "blob".into(),
                format!("o{n}"),
                part_name("aa", n),
            )
        };
        let tree = vec![e(9998), e(10_000), e(9999)];
        let mut all: Vec<TreeEntry> = (0..9998).map(e).collect();
        all.extend(tree);
        let found = find(&all, "aa").unwrap();
        assert_eq!(found.len(), 10_001);
        assert_eq!(found.last().map(String::as_str), Some("o10000"));
    }

    #[test]
    fn part_files_extend_the_base_name() {
        let d = tmpdir("names");
        let mut w = PartWriter::new(&d.join("pack.tmp"), 4);
        w.write_all(&[1; 5]).unwrap();
        let paths = w.finish().unwrap();
        assert_eq!(paths, [d.join("pack.tmp.part0"), d.join("pack.tmp.part1")]);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn find_prefers_the_whole_blob_and_stops_at_a_gap() {
        let e = |name: &str, oid: &str| -> TreeEntry {
            ("100644".into(), "blob".into(), oid.into(), name.into())
        };
        let tree = vec![
            e(&part_name("aa", 0), "o0"),
            e(&part_name("aa", 1), "o1"),
            e(&part_name("aa", 3), "o3"),
            e("bb.age", "whole"),
            e(&part_name("bb", 0), "ignored"),
        ];
        assert_eq!(find(&tree, "aa").unwrap(), ["o0", "o1"]);
        assert_eq!(find(&tree, "bb").unwrap(), ["whole"]);
        assert!(find(&tree, "cc").is_none());
    }
}
