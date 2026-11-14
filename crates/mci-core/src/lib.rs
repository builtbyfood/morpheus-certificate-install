//! morpheus-certificate-install 0.4.2 — core library (no Tauri, no I/O except AIA fetch via a caller-supplied closure).
//!
//! Ported and golden-tested from the Python reference (reference/python, 0.2.1):
//!   quote, names, morpheus_rb, runner, appliance, export::install_text
//! Ported from the reference too, checked by the parity tests (tests/parity.rs):
//!   formats (read anything a CA sends), analyze (chain + checks), aia (complete chain), export::build_files

pub mod quote;
pub mod names;
pub mod morpheus_rb;
pub mod runner;
pub mod appliance;
pub mod model;
pub mod formats;
pub mod analyze;
pub mod aia;
pub mod export;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Product name as shown in the UI, runner headers and INSTALL.txt.
pub const PRODUCT: &str = "Morpheus Certificate Install";
/// Name used in paths, unit names and markers on the appliance.
pub const SLUG: &str = "morpheus-certificate-install";
