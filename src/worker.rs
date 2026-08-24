//! Parallel file-processing pool shared by scan / check / parity sync / import.

use crate::hash::Algo;
use crate::mts::{self, SetLayout};
use crate::parity::{self, BlockCheck, EncodeMember, EncodeSetError};
use crate::util::{fmt_bytes, path_display};
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// One file destined for a parity set.
#[derive(Debug, Clone)]
pub struct SetMember {
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub size: u64,
    pub mtime_ns: i64,
    /// Known content hash (rebuilds); None for files not hashed yet (ingest).
    pub expected_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum Work {
    /// Hash the whole file.
    Hash,
    /// Per-block verification of one set member against its set sidecar
    /// (also yields the member's whole-content hash).
    CheckBlocks { sidecar: PathBuf, ord: usize },
    /// Read every member once, in order, writing a new set sidecar.
    EncodeSet { members: Vec<SetMember> },
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

/// Result of an EncodeSet job. Members that could not be read (EIO, changed
/// size, vanished) are ejected and the set re-encoded from the rest, so
/// `members`/`member_hashes` describe what the sidecar actually contains.
#[derive(Debug)]
pub struct SetEncodeReport {
    pub layout: SetLayout,
    pub set_id: Vec<u8>,
    /// Final (content-addressed) sidecar path; empty set id = nothing written.
    pub sidecar: PathBuf,
    pub members: Vec<SetMember>,
    pub member_hashes: Vec<Vec<u8>>,
    pub bytes: u64,
    /// (member, error, was-EIO) for every ejected member.
    pub ejected: Vec<(SetMember, String, bool)>,
}

#[derive(Debug)]
pub enum Done {
    Hashed { hash: Vec<u8>, bytes: u64 },
    /// Sidecar exists but is damaged/unreadable: only a whole-file hash.
    HashedNoTable { hash: Vec<u8> },
    Blocks(BlockCheck),
    SetEncoded(SetEncodeReport),
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
    pub parity_min_bytes: u64,
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
            parity_min_bytes: a.config.parity_min_bytes,
            parity_dir: a.parity_dir(),
            threads: a.config.jobs(jobs),
            quiet,
        }
    }
    pub fn set_layout_for(&self, member_sizes: Vec<u64>) -> Result<SetLayout> {
        SetLayout::choose(member_sizes, self.block_size, self.stripe_size, self.parity_ppm, self.parity_min_bytes)
    }
}

fn encode_set_job(job_id: usize, members: &[SetMember], s: &Settings) -> Result<SetEncodeReport> {
    let tmp_dir = s.parity_dir.join("tmp");
    std::fs::create_dir_all(&tmp_dir)?;
    let tmp = tmp_dir.join(format!("{}-{}.mts", std::process::id(), job_id));
    let mut remaining: Vec<SetMember> = members.to_vec();
    let mut ejected: Vec<(SetMember, String, bool)> = Vec::new();
    loop {
        if remaining.is_empty() {
            return Ok(SetEncodeReport {
                layout: s.set_layout_for(vec![64])?, // placeholder, unused when set_id is empty
                set_id: vec![],
                sidecar: PathBuf::new(),
                members: vec![],
                member_hashes: vec![],
                bytes: 0,
                ejected,
            });
        }
        let layout = s.set_layout_for(remaining.iter().map(|m| m.size).collect())?;
        let ems: Vec<EncodeMember> = remaining
            .iter()
            .map(|m| EncodeMember { abs: m.abs.clone(), size: m.size, expected_hash: m.expected_hash.clone() })
            .collect();
        match parity::encode_set(&ems, s.algo, &layout, &tmp) {
            Ok(enc) => {
                let final_path = mts::sidecar_path(&s.parity_dir, &enc.set_id);
                if let Some(p) = final_path.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::rename(&tmp, &final_path)?;
                return Ok(SetEncodeReport {
                    layout,
                    set_id: enc.set_id,
                    sidecar: final_path,
                    members: remaining,
                    member_hashes: enc.member_hashes,
                    bytes: enc.bytes_read,
                    ejected,
                });
            }
            Err(EncodeSetError::Member { index, msg, eio }) => {
                let m = remaining.remove(index);
                ejected.push((m, msg, eio));
                // retry with the remaining members
            }
            Err(EncodeSetError::Other(e)) => return Err(e),
        }
    }
}

fn process(job_id: usize, abs: &Path, _size: u64, work: &Work, s: &Settings) -> Done {
    let r: Result<Done> = (|| {
        match work {
            Work::Hash => {
                let (hash, bytes) = parity::hash_file(abs, s.algo)?;
                Ok(Done::Hashed { hash, bytes })
            }
            Work::CheckBlocks { sidecar, ord } => {
                let sc = match mts::Reader::open(sidecar) {
                    Ok(sc) if sc.table_ok() => sc,
                    _ => {
                        let (hash, _) = parity::hash_file(abs, s.algo)?;
                        return Ok(Done::HashedNoTable { hash });
                    }
                };
                Ok(Done::Blocks(parity::check_member(abs, &sc, *ord)?))
            }
            Work::EncodeSet { members } => Ok(Done::SetEncoded(encode_set_job(job_id, members, s)?)),
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
    pb.set_message(format!("{n} jobs"));

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
        eprintln!("processed {n} jobs, {}", fmt_bytes(total_bytes));
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
