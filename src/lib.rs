//! Library surface for `waybar_lan`: the domain/app/infra ring layering,
//! exposed so `tests/` can exercise the network-facing integration tests
//! against the real public API surface — the `waybar_lan` binary
//! (`main.rs`) is a thin composition-root wrapper over this.

#![allow(clippy::upper_case_acronyms)] // NAS is standard industry acronym

pub mod app;
pub mod domain;
pub mod infra;
