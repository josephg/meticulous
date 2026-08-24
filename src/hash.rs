//! Hash algorithms. Every digest stored by meticulous is tagged with its algorithm.
//!
//! Only two are supported, and both are cryptographic with 256-bit digests:
//! * `blake3` (default) — fastest by a wide margin on any hardware (~6.7 GiB/s
//!   per core here), verifiable with `b3sum -c`.
//! * `sha256` — for interoperability with `sha256sum -c` and anywhere a
//!   universally-implemented hash is wanted. Roughly 2.5 GiB/s per core on CPUs
//!   with SHA-NI and ~8x slower on CPUs without it, so prefer blake3 unless the
//!   interop matters.
//!
//! Non-cryptographic (`fletcher4`) and broken (`md5`, `sha1`) algorithms used to
//! be supported for ZFS and legacy-checksum-list import; both goals were dropped
//! and so were the algorithms.

use anyhow::{Result, bail};
use sha2::Digest as _;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Algo {
    Blake3,
    Sha256,
}

impl Algo {
    pub const ALL: &'static [Algo] = &[Algo::Blake3, Algo::Sha256];

    /// Every supported algorithm produces a 32-byte digest.
    pub const DIGEST_LEN: usize = 32;

    pub fn name(self) -> &'static str {
        match self {
            Algo::Blake3 => "blake3",
            Algo::Sha256 => "sha256",
        }
    }

    /// Numeric id used in the binary sidecar format. Never reuse numbers.
    /// (3=sha512-256, 4=fletcher4, 5=md5 and 6=sha1 were removed and are retired.)
    pub fn id(self) -> u8 {
        match self {
            Algo::Blake3 => 1,
            Algo::Sha256 => 2,
        }
    }

    pub fn from_id(id: u8) -> Option<Algo> {
        Algo::ALL.iter().copied().find(|a| a.id() == id)
    }

    pub fn digest_len(self) -> usize {
        Algo::DIGEST_LEN
    }

    pub fn hasher(self) -> Box<dyn Hasher> {
        match self {
            Algo::Blake3 => Box::new(blake3::Hasher::new()),
            Algo::Sha256 => Box::new(sha2::Sha256::new()),
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.hasher();
        h.update(data);
        h.finish()
    }

    /// Name of the coreutils-style tool whose `-c` mode can verify a manifest
    /// produced with this algorithm.
    pub fn manifest_tool(self) -> &'static str {
        match self {
            Algo::Blake3 => "b3sum",
            Algo::Sha256 => "sha256sum",
        }
    }
}

impl fmt::Display for Algo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Algo {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "blake3" | "b3" => Ok(Algo::Blake3),
            "sha256" | "sha-256" => Ok(Algo::Sha256),
            _ => bail!("unknown hash algorithm '{s}' (supported: blake3, sha256)"),
        }
    }
}

/// Streaming hasher. Object-safe so we can hold several in a Vec.
pub trait Hasher: Send {
    fn update(&mut self, data: &[u8]);
    fn finish(self: Box<Self>) -> Vec<u8>;
    /// Finish without consuming (used when hashing blocks and the file at once).
    fn finish_reset(&mut self) -> Vec<u8>;
}

impl Hasher for sha2::Sha256 {
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(self, data)
    }
    fn finish(self: Box<Self>) -> Vec<u8> {
        sha2::Digest::finalize(*self).to_vec()
    }
    fn finish_reset(&mut self) -> Vec<u8> {
        sha2::Digest::finalize_reset(self).to_vec()
    }
}

impl Hasher for blake3::Hasher {
    fn update(&mut self, data: &[u8]) {
        // blake3's update_rayon is faster on big buffers but we are already
        // parallel across files; plain update keeps memory bandwidth sane.
        blake3::Hasher::update(self, data);
    }
    fn finish(self: Box<Self>) -> Vec<u8> {
        self.finalize().as_bytes().to_vec()
    }
    fn finish_reset(&mut self) -> Vec<u8> {
        let out = self.finalize().as_bytes().to_vec();
        self.reset();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vector() {
        let d = Algo::Sha256.hash(b"abc");
        assert_eq!(
            hex::encode(d),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn blake3_vector() {
        let d = Algo::Blake3.hash(b"");
        assert_eq!(
            hex::encode(d),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let data: Vec<u8> = (0..1003u32).map(|i| (i * 7 % 251) as u8).collect();
        for &algo in Algo::ALL {
            let whole = algo.hash(&data);
            let mut h = algo.hasher();
            for ch in data.chunks(13) {
                h.update(ch);
            }
            assert_eq!(h.finish(), whole, "{algo} streaming != one-shot");
            // finish_reset leaves a fresh hasher behind.
            let mut h = algo.hasher();
            h.update(&data);
            assert_eq!(h.finish_reset(), whole);
            h.update(&data);
            assert_eq!(h.finish(), whole);
        }
    }

    #[test]
    fn all_algos_are_32_bytes_with_stable_ids() {
        for &algo in Algo::ALL {
            assert_eq!(algo.digest_len(), 32);
            assert_eq!(algo.hash(b"x").len(), 32);
            assert_eq!(Algo::from_id(algo.id()), Some(algo));
            assert_eq!(algo.name().parse::<Algo>().unwrap(), algo);
        }
        // Retired ids must not come back as something else.
        for id in [0u8, 3, 4, 5, 6, 7, 255] {
            assert_eq!(Algo::from_id(id), None, "id {id} should be unused");
        }
    }

    #[test]
    fn unknown_names_rejected() {
        for s in ["md5", "sha1", "fletcher4", "sha512-256", ""] {
            assert!(s.parse::<Algo>().is_err(), "'{s}' should not parse");
        }
    }
}
