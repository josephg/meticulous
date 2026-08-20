//! Parallel file-processing pool shared by scan / check / parity sync / import.

use crate::csp::{self, Layout};
use crate::hash::Algo;
use crate::parity::{self, BlockCheck};
use crate::util::{fmt_bytes, path_display};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Work {
    /// Hash the whole file; if `parity` also write a sidecar keyed by content hash.
    Hash { parity: bool },
    /// Per-block verification against an existing sidecar (also yields file hash).
    CheckBlocks { sidecar: PathBuf },
}

#[derive(Debug)]
pub struct Job<T> {
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub size: u64,
    pub work: Work,
    /// Caller-defined context passed back with the result.
    pub tag: T,
}

#[derive(Debug)]
pub enum Done {
    Hashed { hash: Vec<u8>, bytes: u64, layout: Option<Layout> },
    /// Sidecar exists but is damaged/unreadable: only a whole-file hash.
    HashedNoTable { hash: Vec<u8> },
    Blocks(BlockCheck),
    Failed(String),
    /// The OS refused to read part of the file (EIO). On ZFS this means the
    /// filesystem's own checksum failed and could not be healed.
    ReadError(String),
}

fn is_eio(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(5) || io.kind() == std::io::ErrorKind::InvalidData)
    })
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub algo: Algo,
    pub block_size: u32,
    pub stripe_size: u64,
    pub parity_ppm: u32,
    pub parity_dir: PathBuf,
    pub threads: usize,
    pub quiet: bool,
}

impl Settings {
    pub fn from_archive(a: &crate::config::Archive, jobs: Option<usize>, quiet: bool) -> Settings {
        Settings {
            algo: a.config.algo,
            block_size: a.config.block_size,
            stripe_size: a.config.stripe_size,
            parity_ppm: a.config.parity_ppm,
            parity_dir: a.parity_dir(),
            threads: a.config.jobs(jobs),
            quiet,
        }
    }
    pub fn layout_for(&self, size: u64) -> Layout {
        Layout::choose(size, self.block_size, self.stripe_size, self.parity_ppm)
    }
}

fn process(job_id: usize, abs: &Path, size: u64, work: &Work, s: &Settings) -> Done {
    let r: Result<Done> = (|| {
        match work {
            Work::Hash { parity: false } => {
                let (hash, bytes) = parity::hash_file(abs, s.algo)?;
                Ok(Done::Hashed { hash, bytes, layout: None })
            }
            Work::Hash { parity: true } => {
                let layout = s.layout_for(size);
                let tmp_dir = s.parity_dir.join("tmp");
                std::fs::create_dir_all(&tmp_dir)?;
                let tmp = tmp_dir.join(format!("{}-{}.csp", std::process::id(), job_id));
                let enc = parity::encode_file(abs, s.algo, layout, &tmp)?;
                let final_path = csp::sidecar_path(&s.parity_dir, &enc.file_hash);
                if final_path.exists() {
                    // Same content already has parity (duplicate file).
                    let _ = std::fs::remove_file(&tmp);
                } else {
                    if let Some(p) = final_path.parent() {
                        std::fs::create_dir_all(p)?;
                    }
                    std::fs::rename(&tmp, &final_path)?;
                }
                Ok(Done::Hashed { hash: enc.file_hash, bytes: enc.bytes_read, layout: Some(layout) })
            }
            Work::CheckBlocks { sidecar } => {
                let sc = match csp::Reader::open(sidecar) {
                    Ok(sc) if sc.table_ok() => sc,
                    _ => {
                        let (hash, _) = parity::hash_file(abs, s.algo)?;
                        return Ok(Done::HashedNoTable { hash });
                    }
                };
                Ok(Done::Blocks(parity::check_blocks(abs, &sc)?))
            }
        }
    })();
    match r {
        Ok(d) => d,
        Err(e) if is_eio(&e) => Done::ReadError(format!("{e:#}")),
        Err(e) => Done::Failed(format!("{e:#}")),
    }
}

/// Run all jobs on a thread pool; `on_done` is called on the calling thread
/// for each finished job (in completion order). Returns when all are done.
pub fn run<T: Send + 'static>(
    jobs: Vec<Job<T>>,
    settings: &Settings,
    mut on_done: impl FnMut(Job<T>, Done) -> Result<()>,
) -> Result<()> {
    if jobs.is_empty() {
        return Ok(());
    }
    let total_bytes: u64 = jobs.iter().map(|j| j.size).sum();
    let n = jobs.len();
    let pb = if settings.quiet || !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(total_bytes);
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta}) {msg}")
                .unwrap()
                .progress_chars("=> "),
        );
        pb.enable_steady_tick(Duration::from_millis(200));
        pb
    };
    pb.set_message(format!("{n} files"));

    let pool = rayon::ThreadPoolBuilder::new().num_threads(settings.threads).build()?;
    let (tx, rx) = mpsc::sync_channel::<(usize, Done)>(settings.threads * 4);
    // Keep the jobs here; workers only need (id, abs, size, work).
    let mut slots: Vec<Option<Job<T>>> = jobs.into_iter().map(Some).collect();
    let specs: Vec<(usize, PathBuf, u64, Work)> = slots
        .iter()
        .enumerate()
        .map(|(i, j)| {
            let j = j.as_ref().unwrap();
            (i, j.abs.clone(), j.size, j.work.clone())
        })
        .collect();
    let s = settings.clone();
    let pb2 = pb.clone();
    pool.spawn(move || {
        use rayon::prelude::*;
        specs.into_par_iter().for_each_with(tx, |tx, (i, abs, size, work)| {
            let done = process(i, &abs, size, &work, &s);
            pb2.inc(size);
            let _ = tx.send((i, done));
        });
    });

    let mut finished = 0usize;
    let mut first_err: Option<anyhow::Error> = None;
    let mut discarded = 0usize;
    for (i, done) in rx {
        finished += 1;
        let job = slots[i].take().expect("job delivered twice");
        pb.set_message(format!("{finished}/{n} {}", truncate(&path_display(&job.rel), 50)));
        if first_err.is_none() {
            if let Err(e) = on_done(job, done) {
                first_err = Some(e);
            }
        } else {
            discarded += 1;
        }
    }
    pb.finish_and_clear();
    if let Some(e) = first_err {
        if discarded > 0 {
            eprintln!("error: {discarded} further result(s) were not recorded because of the error above; re-run after fixing it");
        }
        return Err(e);
    }
    if !settings.quiet {
        eprintln!("processed {n} files, {}", fmt_bytes(total_bytes));
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().rev().take(max - 1).collect::<Vec<_>>().into_iter().rev().collect();
        format!("…{tail}")
    }
}
