//! Library behind the `git-remote-enc` remote helper: an end-to-end encrypted
//! git repository stored inside an ordinary git repository. See DESIGN.md.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

pub mod backend;
pub mod config;
pub mod crypto;
pub mod git;
pub mod manifest;
pub mod remote;
pub mod state;
pub mod version;

/// Diagnostics go to stderr: stdout is git's protocol channel.
pub fn info(msg: &str) {
    eprintln!("enc: {msg}");
}
