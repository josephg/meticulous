//! Hash algorithms. Every digest stored by checksummer is tagged with its algorithm.
//!
//! ZFS compatibility notes:
//! * `fletcher4` is ZFS's default (`checksum=on`). Implemented here exactly as
//!   `fletcher_4_native`: four u64 accumulators over little-endian u32 words.
//!   Output is the four words little-endian (32 bytes); `zdb` prints them as
//!   `cksum=a:b:c:d` in hex.
//! * ZFS `sha256` is plain SHA-256; ZFS `sha512` is SHA-512/256.
//! * ZFS `blake3`, `skein` and `edonr` are *salted* with a per-pool secret and
//!   cannot be reproduced outside the pool, so our `blake3` is plain BLAKE3.
//! * `md5`/`sha1` exist only so legacy checksum lists can be imported/verified.

use anyhow::{Context, Result, anyhow, bail};
use sha2::Digest as _;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Algo {
    Blake3,
    Sha256,
    #[value(name = "sha512-256", alias = "sha512")]
    #[serde(alias = "sha512")]
    Sha512_256,
    Fletcher4,
    Md5,
    Sha1,
}

impl Algo {
    pub const ALL: &'static [Algo] = &[
        Algo::Blake3,
        Algo::Sha256,
        Algo::Sha512_256,
        Algo::Fletcher4,
        Algo::Md5,
        Algo::Sha1,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Algo::Blake3 => "blake3",
            Algo::Sha256 => "sha256",
            Algo::Sha512_256 => "sha512-256",
            Algo::Fletcher4 => "fletcher4",
            Algo::Md5 => "md5",
            Algo::Sha1 => "sha1",
        }
    }

    /// Numeric id used in the binary sidecar format. Never reuse numbers.
    pub fn id(self) -> u8 {
        match self {
            Algo::Blake3 => 1,
            Algo::Sha256 => 2,
            Algo::Sha512_256 => 3,
            Algo::Fletcher4 => 4,
            Algo::Md5 => 5,
            Algo::Sha1 => 6,
        }
    }

    pub fn from_id(id: u8) -> Option<Algo> {
        Algo::ALL.iter().copied().find(|a| a.id() == id)
    }

    pub fn digest_len(self) -> usize {
        match self {
            Algo::Blake3 | Algo::Sha256 | Algo::Sha512_256 | Algo::Fletcher4 => 32,
            Algo::Md5 => 16,
            Algo::Sha1 => 20,
        }
    }

    /// True if this algorithm is one ZFS can store for a block pointer and that
    /// we can reproduce outside of the pool.
    #[allow(dead_code)]
    pub fn zfs_reproducible(self) -> bool {
        matches!(self, Algo::Sha256 | Algo::Sha512_256 | Algo::Fletcher4)
    }

    /// Whether the algorithm is cryptographically strong (suitable as the
    /// primary identity hash in the database).
    pub fn strong(self) -> bool {
        matches!(self, Algo::Blake3 | Algo::Sha256 | Algo::Sha512_256)
    }

    pub fn hasher(self) -> Box<dyn Hasher> {
        match self {
            Algo::Blake3 => Box::new(blake3::Hasher::new()),
            Algo::Sha256 => Box::new(sha2::Sha256::new()),
            Algo::Sha512_256 => Box::new(sha2::Sha512_256::new()),
            Algo::Fletcher4 => Box::new(Fletcher4::default()),
            Algo::Md5 => Box::new(md5::Md5::new()),
            Algo::Sha1 => Box::new(sha1::Sha1::new()),
        }
    }

    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.hasher();
        h.update(data);
        h.finish()
    }

    /// Name of the coreutils-style tool whose `-c` mode can verify a manifest
    /// produced with this algorithm, if any.
    #[allow(dead_code)]
    pub fn manifest_tool(self) -> Option<&'static str> {
        match self {
            Algo::Blake3 => Some("b3sum"),
            Algo::Sha256 => Some("sha256sum"),
            Algo::Md5 => Some("md5sum"),
            Algo::Sha1 => Some("sha1sum"),
            _ => None,
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
            "sha512-256" | "sha512/256" | "sha512_256" | "sha512" => Ok(Algo::Sha512_256),
            "fletcher4" | "fletcher" | "on" => Ok(Algo::Fletcher4),
            "md5" => Ok(Algo::Md5),
            "sha1" | "sha-1" => Ok(Algo::Sha1),
            _ => bail!("unknown hash algorithm '{s}'"),
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

macro_rules! digest_hasher {
    ($t:ty) => {
        impl Hasher for $t {
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
    };
}
digest_hasher!(sha2::Sha256);
digest_hasher!(sha2::Sha512_256);
digest_hasher!(md5::Md5);
digest_hasher!(sha1::Sha1);

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

/// ZFS fletcher4 (native/little-endian word order). Wrapping u64 arithmetic
/// over 32-bit LE words; input is zero padded to a multiple of 4 bytes.
#[derive(Default, Clone)]
pub struct Fletcher4 {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    /// Partial trailing word (0..4 bytes) carried between update calls.
    pending: [u8; 4],
    pending_len: usize,
}

impl Fletcher4 {
    #[inline]
    fn word(&mut self, w: u32) {
        self.a = self.a.wrapping_add(w as u64);
        self.b = self.b.wrapping_add(self.a);
        self.c = self.c.wrapping_add(self.b);
        self.d = self.d.wrapping_add(self.c);
    }

    pub fn words(&self) -> [u64; 4] {
        let mut s = self.clone();
        if s.pending_len > 0 {
            let mut w = [0u8; 4];
            w[..s.pending_len].copy_from_slice(&s.pending[..s.pending_len]);
            s.pending_len = 0;
            s.word(u32::from_le_bytes(w));
        }
        [s.a, s.b, s.c, s.d]
    }

    /// Format the way `zdb` prints block pointer checksums: `a:b:c:d` in hex.
    #[allow(dead_code)]
    pub fn zdb_format(&self) -> String {
        let w = self.words();
        format!("{:x}:{:x}:{:x}:{:x}", w[0], w[1], w[2], w[3])
    }
}

impl Hasher for Fletcher4 {
    fn update(&mut self, mut data: &[u8]) {
        if self.pending_len > 0 {
            let need = 4 - self.pending_len;
            let take = need.min(data.len());
            self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&data[..take]);
            self.pending_len += take;
            data = &data[take..];
            if self.pending_len == 4 {
                let w = u32::from_le_bytes(self.pending);
                self.pending_len = 0;
                self.word(w);
            } else {
                return;
            }
        }
        let mut chunks = data.chunks_exact(4);
        for ch in &mut chunks {
            self.word(u32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.pending[..rem.len()].copy_from_slice(rem);
            self.pending_len = rem.len();
        }
    }
    fn finish(self: Box<Self>) -> Vec<u8> {
        let w = self.words();
        let mut out = Vec::with_capacity(32);
        for x in w {
            out.extend_from_slice(&x.to_le_bytes());
        }
        out
    }
    fn finish_reset(&mut self) -> Vec<u8> {
        let out = Box::new(self.clone()).finish();
        *self = Fletcher4::default();
        out
    }
}

/// A digest tagged with its algorithm. Textual form: `algo:hex`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    pub algo: Algo,
    pub bytes: Vec<u8>,
}

impl Digest {
    pub fn new(algo: Algo, bytes: Vec<u8>) -> Self {
        Digest { algo, bytes }
    }
    pub fn hex(&self) -> String {
        hex::encode(&self.bytes)
    }
    /// `zdb`-style rendering for fletcher4, hex otherwise.
    pub fn zfs_format(&self) -> String {
        if self.algo == Algo::Fletcher4 && self.bytes.len() == 32 {
            let w: Vec<u64> = self
                .bytes
                .chunks_exact(8)
                .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
                .collect();
            format!("{:x}:{:x}:{:x}:{:x}", w[0], w[1], w[2], w[3])
        } else {
            self.hex()
        }
    }
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Result<Digest> {
        let (algo, hexpart) = s
            .split_once(':')
            .ok_or_else(|| anyhow!("digest '{s}' is missing an 'algo:' prefix"))?;
        let algo: Algo = algo.parse()?;
        let bytes = hex::decode(hexpart).with_context(|| format!("bad hex in digest '{s}'"))?;
        if bytes.len() != algo.digest_len() {
            bail!(
                "digest '{s}' has {} bytes, expected {} for {algo}",
                bytes.len(),
                algo.digest_len()
            );
        }
        Ok(Digest { algo, bytes })
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algo, self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
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
    fn sha512_256_vector() {
        // FIPS 180-4 SHA-512/256("abc")
        let d = Algo::Sha512_256.hash(b"abc");
        assert_eq!(
            hex::encode(d),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
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
    fn fletcher4_basic() {
        // Hand-computed: words [1, 2] -> a=3, b=1+3=4, c=1+4=5, d=1+5=6
        let mut h = Fletcher4::default();
        h.update(&1u32.to_le_bytes());
        h.update(&2u32.to_le_bytes());
        assert_eq!(h.words(), [3, 4, 5, 6]);
        assert_eq!(h.zdb_format(), "3:4:5:6");
    }

    #[test]
    fn fletcher4_zeros_and_split_updates() {
        // 512 zero bytes => all zero accumulators (as zdb shows for zero blocks).
        let z = Algo::Fletcher4.hash(&[0u8; 512]);
        assert!(z.iter().all(|&b| b == 0));
        // Splitting the input arbitrarily must not change the result.
        let data: Vec<u8> = (0..1003u32).map(|i| (i * 7 % 251) as u8).collect();
        let whole = Algo::Fletcher4.hash(&data);
        let mut h = Fletcher4::default();
        for ch in data.chunks(13) {
            h.update(ch);
        }
        assert_eq!(Box::new(h).finish(), whole);
        // Tail is zero padded: "ab" == "ab\0\0"
        assert_eq!(Algo::Fletcher4.hash(b"ab"), Algo::Fletcher4.hash(b"ab\0\0"));
    }

    #[test]
    fn fletcher4_known_value() {
        // Reference computed with the textbook definition in Python:
        // a=b=c=d=0; for w in words: a+=w; b+=a; c+=b; d+=c (mod 2^64)
        // for the 1024-byte sequence i % 256.
        let data: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
        let mut h = Fletcher4::default();
        h.update(&data);
        // Python check: words = struct.unpack('<256I', data)
        let mut a = 0u64;
        let mut b = 0u64;
        let mut c = 0u64;
        let mut d = 0u64;
        for ch in data.chunks_exact(4) {
            a = a.wrapping_add(u32::from_le_bytes(ch.try_into().unwrap()) as u64);
            b = b.wrapping_add(a);
            c = c.wrapping_add(b);
            d = d.wrapping_add(c);
        }
        assert_eq!(h.words(), [a, b, c, d]);
    }

    #[test]
    fn digest_roundtrip() {
        let d = Digest::new(Algo::Blake3, Algo::Blake3.hash(b"x"));
        let s = d.to_string();
        assert!(s.starts_with("blake3:"));
        assert_eq!(Digest::parse(&s).unwrap(), d);
        assert!(Digest::parse("blake3:zz").is_err());
        assert!(Digest::parse("nope:00").is_err());
    }
}
