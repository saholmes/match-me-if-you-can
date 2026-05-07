//! CSV import / export for synthetic populations.
//!
//! The CSV format is the canonical interchange: cheap to inspect,
//! works with `pandas`, `awk`, `cut`, and the standard breach-
//! simulation tools.  Field order is fixed by the Serde derives on
//! [`crate::User`].

use std::path::Path;

use crate::attributes::User;

/// Errors I/O can produce.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// Underlying filesystem error.
    #[error("I/O error: {0}")]
    Fs(#[from] std::io::Error),
    /// CSV parse / serialise error.
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
}

/// Write a population to CSV at `path`.
pub fn write_population(path: impl AsRef<Path>, pop: &[User]) -> Result<(), IoError> {
    let mut wtr = csv::Writer::from_path(path.as_ref())?;
    for u in pop {
        wtr.serialize(u)?;
    }
    wtr.flush()?;
    Ok(())
}

/// Read a population from CSV at `path`.
pub fn read_population(path: impl AsRef<Path>) -> Result<Vec<User>, IoError> {
    let mut rdr = csv::Reader::from_path(path.as_ref())?;
    let mut out = Vec::new();
    for record in rdr.deserialize() {
        let u: User = record?;
        out.push(u);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{generate_population, GenerationConfig};
    use std::env::temp_dir;

    #[test]
    fn roundtrip() {
        let cfg = GenerationConfig { n: 50, ..Default::default() };
        let pop = generate_population(&cfg);
        let path = temp_dir().join("mmiyc-pop-test.csv");
        write_population(&path, &pop).unwrap();
        let read_back = read_population(&path).unwrap();
        assert_eq!(pop, read_back);
        std::fs::remove_file(path).ok();
    }
}
