//! Type-safe domain models for network monitoring, split by concern:
//! - `values` — simple validated newtypes with no dependency on any other
//!   domain type.
//! - `device` — the device entity: its identity, its data model, and its
//!   state enums.
//! - `inference` — heuristic device-identity classification, a second
//!   `impl NetworkDevice` block kept separate from the entity/data-model
//!   definitions in `device` (see [[domain-module-rules]]).
//! - `snapshot` — top-level aggregates (this host's interfaces, the full
//!   network snapshot).
//! - `vendor` — hardcoded MAC-prefix vendor/platform lookup, per
//!   [[oui-vendor-lookup-and-composed-identity]].
//!
//! - All primitives are wrapped in semantic newtypes
//! - Validation happens at construction time
//! - Invalid states are unrepresentable

mod device;
mod inference;
mod snapshot;
mod values;
mod vendor;

pub use device::*;
pub use snapshot::*;
pub use values::*;
pub use vendor::*;
