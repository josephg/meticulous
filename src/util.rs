use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn fmt_time(ts: i64) -> String {
    match jiff::Timestamp::from_second(ts) {
        Ok(t) => t
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%d %H:%M:%S")
            .to_string(),
        Err(_) => ts.to_string(),
    }
}

pub fn fmt_opt_time(ts: Option<i64>) -> String {
    ts.map(fmt_time).unwrap_or_else(|| "never".into())
}

pub fn fmt_bytes(n: u64) -> String {
    bytesize::ByteSize::b(n).display().iec().to_string()
}

pub fn fmt_ago(ts: i64) -> String {
    let d = now() - ts;
    if d < 0 {
        return "in the future".into();
    }
    let d = d as u64;
    if d < 120 {
        format!("{d}s ago")
    } else if d < 7200 {
        format!("{}m ago", d / 60)
    } else if d < 172_800 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

/// Parse a size like "64KiB", "5M", "1.5 GB" into bytes.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let bs: bytesize::ByteSize = s
        .parse()
        .map_err(|e: String| anyhow::anyhow!("bad size '{s}': {e}"))?;
    Ok(bs.as_u64())
}

/// Parse "5%" or "0.05" or "5" (percent) into parts-per-million.
pub fn parse_parity(s: &str) -> Result<u32> {
    let s = s.trim();
    let pct: f64 = if let Some(p) = s.strip_suffix('%') {
        p.trim().parse().with_context(|| format!("bad parity '{s}'"))?
    } else {
        let v: f64 = s.parse().with_context(|| format!("bad parity '{s}'"))?;
        if v < 1.0 { v * 100.0 } else { v }
    };
    if !(0.0..=100.0).contains(&pct) {
        bail!("parity percentage {pct} out of range 0..100");
    }
    Ok((pct * 10_000.0).round() as u32)
}

pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    humantime::parse_duration(s.trim()).with_context(|| format!("bad duration '{s}'"))
}

/// Answer to use for interactive prompts when not asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assume {
    Ask,
    Yes,
    No,
}

/// Ask a yes/no question. Non-TTY stdin => `default`.
pub fn confirm(question: &str, assume: Assume, default: bool) -> bool {
    match assume {
        Assume::Yes => return true,
        Assume::No => return false,
        Assume::Ask => {}
    }
    if !std::io::stdin().is_terminal() {
        return default;
    }
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("{question} {hint} ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return default;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => return default,
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("please answer y or n"),
        }
    }
}

/// coreutils-style escaping for manifest lines: returns (needs_backslash_prefix, escaped bytes).
pub fn escape_manifest_path(p: &[u8]) -> (bool, Vec<u8>) {
    if !p.iter().any(|&b| b == b'\n' || b == b'\\' || b == b'\r') {
        return (false, p.to_vec());
    }
    let mut out = Vec::with_capacity(p.len() + 8);
    for &b in p {
        match b {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            _ => out.push(b),
        }
    }
    (true, out)
}

/// Single left-to-right unescape (inverse of `escape_manifest_path`).
pub fn unescape_manifest_path(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        if p[i] == b'\\' && i + 1 < p.len() {
            match p[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b'\\' => out.push(b'\\'),
                other => {
                    out.push(b'\\');
                    out.push(other);
                }
            }
            i += 2;
        } else {
            out.push(p[i]);
            i += 1;
        }
    }
    out
}

/// Archive-relative path <-> bytes (as stored in the DB).
pub fn path_bytes(p: &Path) -> &[u8] {
    p.as_os_str().as_bytes()
}
pub fn path_from_bytes(b: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsStr::from_bytes(b))
}
pub fn path_display(p: &Path) -> String {
    String::from_utf8_lossy(path_bytes(p)).into_owned()
}

/// Make a user-supplied path archive-relative. Accepts absolute paths, paths
/// relative to the CWD, and (if those don't exist) paths relative to root.
pub fn to_relative(root: &Path, arg: &Path) -> Result<PathBuf> {
    let root_c = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let candidates = [std::path::absolute(arg).ok(), Some(root.join(arg))];
    for cand in candidates.into_iter().flatten() {
        let c = std::fs::canonicalize(&cand).unwrap_or(cand);
        if let Ok(rel) = c.strip_prefix(&root_c) {
            return Ok(normalize_rel(rel));
        }
    }
    bail!("path '{}' is not inside the archive root {}", arg.display(), root.display())
}

/// Strip leading "./" and trailing "/" from an already-relative path.
pub fn normalize_rel(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(s) => out.push(s),
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_sizes() {
        assert_eq!(parse_size("64KiB").unwrap(), 65536);
        assert_eq!(parse_size("1MiB").unwrap(), 1 << 20);
        assert_eq!(parse_size("100").unwrap(), 100);
    }
    #[test]
    fn parse_parity_forms() {
        assert_eq!(parse_parity("5%").unwrap(), 50_000);
        assert_eq!(parse_parity("5").unwrap(), 50_000);
        assert_eq!(parse_parity("0.05").unwrap(), 50_000);
        assert_eq!(parse_parity("12.5%").unwrap(), 125_000);
        assert!(parse_parity("150%").is_err());
    }
    #[test]
    fn manifest_escape_roundtrip() {
        for name in [&b"plain"[..], b"a\\nb", b"a\nb", b"x\\\\y", b"\xff\xfe caf\xe9"] {
            let (_flag, esc) = escape_manifest_path(name);
            assert!(!esc.contains(&b'\n'));
            assert_eq!(unescape_manifest_path(&esc), name, "{name:?}");
        }
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_rel(Path::new("./a/b/")), PathBuf::from("a/b"));
        assert_eq!(normalize_rel(Path::new("a/../b")), PathBuf::from("b"));
    }
}
