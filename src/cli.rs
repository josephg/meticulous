use crate::config::ParityMode;
use crate::db::State;
use crate::hash::Algo;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// meticulous — keep a bit-rot-resistant index of checksums (and optional
/// Reed–Solomon parity) for an archive directory.
///
/// All paths printed or accepted are relative to the archive root: the
/// directory containing `_meticulous/`. The root is found by walking up from
/// the current directory, or given with --root.
#[derive(Parser, Debug)]
#[command(name = "meticulous", version, about, long_about = None, propagate_version = true)]
pub struct Cli {
    /// Archive root (default: discovered from the current directory).
    #[arg(long, global = true, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Less output (only problems and the final summary).
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Machine-readable JSON output where supported.
    #[arg(long, global = true)]
    pub json: bool,

    /// Answer "yes" to interactive prompts.
    #[arg(short = 'y', long, global = true, conflicts_with = "no")]
    pub yes: bool,

    /// Answer "no" to interactive prompts.
    #[arg(short = 'n', long, global = true)]
    pub no: bool,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new archive: writes <DIR>/_meticulous/{config.toml,index.sqlite}.
    Init(InitArgs),

    /// Re-read files and verify their hashes (everything, or only under PATHS).
    #[command(visible_alias = "verify")]
    Check(CheckArgs),

    /// Find added / removed / modified files and update the index.
    Scan(ScanArgs),

    /// Accept the current on-disk content of files as the new truth (use after
    /// `scan` reported SUSPECTED CORRUPTION for something you really did edit).
    Accept(AcceptArgs),

    /// Rebuild damaged files from their Reed–Solomon parity.
    Repair(RepairArgs),

    /// Manage which directories store parity, and synchronise parity data.
    #[command(subcommand)]
    Parity(ParityCmd),

    /// Summary of the archive's health.
    Status,

    /// List indexed files.
    Ls(LsArgs),

    /// Show everything known about one file.
    Show { path: PathBuf },

    /// Show the event log (adds, changes, corruption, repairs...).
    History(HistoryArgs),

    /// Write a plaintext checksum manifest (b3sum/sha256sum compatible).
    Export(ExportArgs),

    /// Verify files against an existing checksum list (md5sum/sha256sum/b3sum
    /// format) and index any files not yet known.
    Import(ImportArgs),

    /// Check the index database and parity store for damage.
    Fsck(FsckArgs),

    /// Show or change configuration.
    Config(ConfigArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Directory to become the archive root (default: current directory).
    pub dir: Option<PathBuf>,
    /// Hash algorithm for file checksums.
    #[arg(long, value_enum, default_value = "blake3")]
    pub algo: Algo,
    /// Parity/verification block size (multiple of 64), e.g. 64KiB, 128KiB.
    #[arg(long, default_value = "64KiB")]
    pub block_size: String,
    /// Parity amount as a percentage of data, e.g. "5%".
    #[arg(long, default_value = "5%")]
    pub parity: String,
    /// Data bytes per Reed–Solomon stripe (bounds memory per worker).
    #[arg(long, default_value = "128MiB")]
    pub stripe_size: String,
    /// Whether directories without an explicit mark store parity.
    #[arg(long, value_enum, default_value = "exclude")]
    pub parity_default: ParityMode,
    /// Glob pattern(s) of paths to ignore (relative to the root). Repeatable.
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,
    /// Default number of worker threads (0 = auto).
    #[arg(long, default_value_t = 0)]
    pub jobs: usize,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Files or directories to check (default: whole archive).
    pub paths: Vec<PathBuf>,
    /// Only check files not verified within this long (e.g. 30d, 12h).
    #[arg(long, value_name = "DURATION")]
    pub older_than: Option<String>,
    /// Stop after reading about this many bytes, least-recently-verified first.
    #[arg(long, value_name = "SIZE")]
    pub budget: Option<String>,
    /// Attempt to repair corrupt files that have parity.
    #[arg(long)]
    pub repair: bool,
    /// Worker threads.
    #[arg(short, long)]
    pub jobs: Option<usize>,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Restrict the scan to these files/directories (default: whole archive).
    pub paths: Vec<PathBuf>,
    /// Report files whose size/mtime changed but do not re-hash/accept them.
    #[arg(long)]
    pub no_accept_changes: bool,
    /// Do not generate parity for newly added files (even if covered).
    #[arg(long)]
    pub no_parity: bool,
    /// Worker threads.
    #[arg(short, long)]
    pub jobs: Option<usize>,
}

#[derive(Args, Debug)]
pub struct AcceptArgs {
    /// Files (or directories: every flagged file under them) to accept.
    pub paths: Vec<PathBuf>,
    #[arg(short, long)]
    pub jobs: Option<usize>,
}

#[derive(Args, Debug)]
pub struct RepairArgs {
    /// Files or directories to repair (corrupt files under them).
    pub paths: Vec<PathBuf>,
    /// Keep the damaged original as <name>.corrupt.
    #[arg(long)]
    pub keep_corrupt: bool,
    /// Show what would be repaired without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug)]
pub enum ParityCmd {
    /// Mark directories as storing parity (their subtrees inherit).
    Include { dirs: Vec<PathBuf> },
    /// Mark directories as NOT storing parity (their subtrees inherit).
    Exclude { dirs: Vec<PathBuf> },
    /// Remove explicit marks so directories inherit again.
    Unmark { dirs: Vec<PathBuf> },
    /// List marks and coverage.
    List,
    /// Generate missing parity for covered files; with --prune, delete parity
    /// for files that are no longer covered.
    Sync {
        #[arg(long)]
        prune: bool,
        #[arg(short, long)]
        jobs: Option<usize>,
    },
}

#[derive(Args, Debug)]
pub struct LsArgs {
    pub paths: Vec<PathBuf>,
    /// Only files in this state.
    #[arg(long, value_enum)]
    pub state: Option<State>,
    /// Only files with (or, with --no-parity, without) parity.
    #[arg(long, conflicts_with = "no_parity")]
    pub parity: bool,
    #[arg(long)]
    pub no_parity: bool,
    /// Show hashes.
    #[arg(short, long)]
    pub long: bool,
}

#[derive(Args, Debug)]
pub struct HistoryArgs {
    pub path: Option<PathBuf>,
    /// Only events newer than this (e.g. 7d).
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output file (default: stdout). `scan` always refreshes _meticulous/MANIFEST.txt.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// sum = "<hex>  <path>" (b3sum/sha256sum -c compatible), json = one object per line.
    #[arg(long, default_value = "sum")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Checksum list file (lines of "<hex>  <path>", coreutils style).
    pub file: PathBuf,
    /// Algorithm of the listed hashes (inferred from digest length when unambiguous).
    #[arg(long, value_enum)]
    pub algo: Option<Algo>,
    /// Paths in the list are relative to this directory (default: the list's own directory).
    #[arg(long)]
    pub relative_to: Option<PathBuf>,
    /// Trust listed hashes for files not yet indexed instead of re-reading them
    /// (only possible when the list uses the archive's algorithm).
    #[arg(long)]
    pub trust: bool,
    #[arg(short, long)]
    pub jobs: Option<usize>,
}

#[derive(Args, Debug)]
pub struct FsckArgs {
    /// Also verify every parity sidecar's internal hashes (reads all parity).
    #[arg(long)]
    pub deep: bool,
    /// Fix what can be fixed: clear has_parity for missing sidecars, remove orphan sidecars.
    #[arg(long)]
    pub fix: bool,
    /// Rebuild index.sqlite from MANIFEST.txt, PARITY_MARKS.txt and the parity store.
    #[arg(long)]
    pub rebuild_db: bool,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Key to show/set (algo, block_size, stripe_size, parity, parity_default, exclude, jobs).
    pub key: Option<String>,
    /// New value.
    pub value: Option<String>,
}
