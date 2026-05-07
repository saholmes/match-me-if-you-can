//! Synthetic user populations + breach-simulation harness.
//!
//! Two responsibilities:
//!
//! 1. **Generation**: produce a population of synthetic users with
//!    realistic attribute distributions (age, country, postcode prefix,
//!    email-domain, income bracket).  Realistic enough that the
//!    breach-simulation match rates we report in the paper are
//!    representative.  Not realistic enough to overlap with any
//!    actual identifiable individual.
//!
//! 2. **Breach simulation**: given a "leaked" snapshot of one of the
//!    storage scenarios, attempt to re-identify users by linkage
//!    against an *auxiliary* synthetic database with overlapping
//!    attributes.  The headline metric is the per-attribute and
//!    aggregate re-identification rate.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]

pub mod attributes;
pub mod generate;
pub mod io;
pub mod breach;

pub use attributes::User;
pub use generate::{generate_population, GenerationConfig};
pub use breach::{breach_simulate, BreachResult, AuxiliaryDatabase};
