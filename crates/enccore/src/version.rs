//! The workspace version, and the test that ties it to `CHANGELOG.md`.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[test]
    fn version_matches_changelog() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../CHANGELOG.md");
        let changelog = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        // Newest "## vX.Y.Z" heading in the file.
        let changelog_version = changelog
            .lines()
            .find_map(|line| {
                let rest = line.strip_prefix("## v")?;
                let ver: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                (ver.split('.').count() == 3).then_some(ver)
            })
            .expect("no version header found in CHANGELOG.md");

        assert_eq!(changelog_version, super::VERSION);
    }
}
