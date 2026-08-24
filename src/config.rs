use crate::hash::Algo;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DIR_NAME: &str = "_meticulous";
pub const CONFIG_FILE: &str = "config.toml";
pub const DB_FILE: &str = "index.sqlite";
pub const MANIFEST_FILE: &str = "MANIFEST.txt";
pub const MANIFEST_TSV_FILE: &str = "MANIFEST.tsv";
pub const QUARANTINE_DIR: &str = "quarantine";
pub const LOCK_FILE: &str = "lock";
pub const PARITY_DIR: &str = "parity";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ParityMode {
    Include,
    Exclude,
}

impl ParityMode {
    pub fn name(self) -> &'static str {
        match self {
            ParityMode::Include => "include",
            ParityMode::Exclude => "exclude",
        }
    }
    pub fn parse(s: &str) -> Result<ParityMode> {
        match s {
            "include" => Ok(ParityMode::Include),
            "exclude" => Ok(ParityMode::Exclude),
            _ => bail!("bad parity mode '{s}'"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Hash algorithm for new files.
    pub algo: Algo,
    /// Parity/verification block size in bytes (multiple of 64).
    pub block_size: u32,
    /// Bytes of data per Reed-Solomon stripe (bounds memory use).
    pub stripe_size: u64,
    /// Parity amount in parts per million of data (50000 = 5%).
    pub parity_ppm: u32,
    /// Minimum parity per stripe, in bytes (rounded up to whole blocks).
    /// Set to the ZFS recordsize at init so one lost record is always within
    /// the margin; 0 = no extra floor.
    pub parity_min_bytes: u64,
    /// Whether unmarked directories store parity.
    pub parity_default: ParityMode,
    /// Glob patterns (relative to root) to skip.
    pub exclude: Vec<String>,
    /// Default worker threads (0 = auto).
    pub jobs: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            algo: Algo::Blake3,
            block_size: 64 * 1024,
            stripe_size: 128 << 20,
            parity_ppm: 50_000,
            parity_min_bytes: 0,
            parity_default: ParityMode::Exclude,
            exclude: vec![],
            jobs: 0,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config = toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        c.validate()?;
        Ok(c)
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let header = "# meticulous archive configuration\n# block_size / stripe_size are bytes; parity_ppm is parts-per-million of data (50000 = 5%).\n\n";
        std::fs::write(path, format!("{header}{}", toml::to_string_pretty(self)?))
            .with_context(|| format!("writing {}", path.display()))
    }
    pub fn validate(&self) -> Result<()> {
        if self.block_size < 64 || !self.block_size.is_multiple_of(64) || self.block_size > crate::mts::MAX_BLOCK_SIZE {
            bail!("block_size must be a multiple of 64 between 64 and {}", crate::mts::MAX_BLOCK_SIZE);
        }
        if self.stripe_size < self.block_size as u64 * 64 {
            bail!("stripe_size must be at least 64 × block_size ({} bytes)", self.block_size as u64 * 64);
        }
        if self.parity_ppm > 1_000_000 {
            bail!("parity_ppm must be <= 1000000");
        }
        if self.parity_min_bytes > self.stripe_size / 4 {
            bail!("parity_min_bytes must be <= stripe_size / 4 ({} bytes)", self.stripe_size / 4);
        }
        Ok(())
    }
    pub fn parity_percent(&self) -> f64 {
        self.parity_ppm as f64 / 10_000.0
    }
    pub fn jobs(&self, override_: Option<usize>) -> usize {
        if let Some(j) = override_ {
            return j.max(1);
        }
        if self.jobs > 0 {
            return self.jobs;
        }
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(1, 4)
    }
    /// Exclude patterns use gitignore-like semantics: a pattern without '/'
    /// matches a file or directory *name* at any depth (`cache`, `*.tmp`);
    /// a pattern containing '/' is anchored at the archive root (`photos/raw`,
    /// `**/.cache/*`). `*` does not cross '/'.
    pub fn exclude_set(&self) -> Result<globset::GlobSet> {
        let mut b = globset::GlobSetBuilder::new();
        for pat in &self.exclude {
            let anchored = pat.contains('/');
            let full = if anchored { pat.trim_start_matches('/').to_string() } else { format!("**/{pat}") };
            let g = globset::GlobBuilder::new(&full)
                .literal_separator(true)
                .build()
                .with_context(|| format!("bad exclude glob '{pat}'"))?;
            b.add(g);
        }
        Ok(b.build()?)
    }
}

/// An opened archive: root dir + paths + config.
#[derive(Debug, Clone)]
pub struct Archive {
    pub root: PathBuf,
    pub config: Config,
}

impl Archive {
    pub fn dir(&self) -> PathBuf {
        self.root.join(DIR_NAME)
    }
    pub fn config_path(&self) -> PathBuf {
        self.dir().join(CONFIG_FILE)
    }
    pub fn db_path(&self) -> PathBuf {
        self.dir().join(DB_FILE)
    }
    pub fn manifest_path(&self) -> PathBuf {
        self.dir().join(MANIFEST_FILE)
    }
    pub fn manifest_tsv_path(&self) -> PathBuf {
        self.dir().join(MANIFEST_TSV_FILE)
    }
    pub fn quarantine_dir(&self) -> PathBuf {
        self.dir().join(QUARANTINE_DIR)
    }
    pub fn lock_path(&self) -> PathBuf {
        self.dir().join(LOCK_FILE)
    }
    pub fn parity_dir(&self) -> PathBuf {
        self.dir().join(PARITY_DIR)
    }
    pub fn abs(&self, rel: &Path) -> PathBuf {
        self.root.join(rel)
    }

    /// Find the archive containing `start` (or the explicit root).
    pub fn discover(explicit: Option<&Path>) -> Result<Archive> {
        let root = match explicit {
            Some(r) => {
                let r = std::fs::canonicalize(r).with_context(|| format!("root {}", r.display()))?;
                if !r.join(DIR_NAME).join(CONFIG_FILE).is_file() {
                    bail!("{} is not a meticulous archive (no {DIR_NAME}/{CONFIG_FILE}); run `meticulous init`", r.display());
                }
                r
            }
            None => {
                let cwd = std::env::current_dir()?;
                let mut cur: Option<&Path> = Some(&cwd);
                let mut found = None;
                while let Some(d) = cur {
                    if d.join(DIR_NAME).join(CONFIG_FILE).is_file() {
                        found = Some(d.to_path_buf());
                        break;
                    }
                    cur = d.parent();
                }
                found.ok_or_else(|| {
                    anyhow::anyhow!(
                        "no meticulous archive found in {} or any parent (looked for {DIR_NAME}/); run `meticulous init` or pass --root",
                        cwd.display()
                    )
                })?
            }
        };
        let config = Config::load(&root.join(DIR_NAME).join(CONFIG_FILE))?;
        Ok(Archive { root, config })
    }
}
