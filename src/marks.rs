//! Parity coverage: which files should have parity, by nearest marked ancestor.

use crate::config::ParityMode;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct Resolver {
    marks: HashMap<PathBuf, ParityMode>,
    default: ParityMode,
    cache: HashMap<PathBuf, (ParityMode, PathBuf)>,
}

impl Resolver {
    pub fn new(marks: HashMap<PathBuf, ParityMode>, default: ParityMode) -> Self {
        Resolver { marks, default, cache: HashMap::new() }
    }

    pub fn marks(&self) -> &HashMap<PathBuf, ParityMode> {
        &self.marks
    }

    /// Effective mode for a *directory* plus the mark that decided it
    /// (empty path + default when nothing is marked).
    pub fn resolve_dir(&mut self, dir: &Path) -> (ParityMode, PathBuf) {
        if let Some(v) = self.cache.get(dir) {
            return v.clone();
        }
        let mut cur = Some(dir);
        let mut result = None;
        while let Some(d) = cur {
            if let Some(m) = self.marks.get(d) {
                result = Some((*m, d.to_path_buf()));
                break;
            }
            cur = d.parent();
        }
        let r = result.unwrap_or((self.default, PathBuf::new()));
        self.cache.insert(dir.to_path_buf(), r.clone());
        r
    }

    /// Should this *file* have parity?
    pub fn covers_file(&mut self, file: &Path) -> bool {
        let dir = file.parent().unwrap_or(Path::new(""));
        self.resolve_dir(dir).0 == ParityMode::Include
    }

    pub fn explain_file(&mut self, file: &Path) -> (ParityMode, PathBuf) {
        let dir = file.parent().unwrap_or(Path::new(""));
        self.resolve_dir(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nearest_ancestor_wins() {
        let mut m = HashMap::new();
        m.insert(PathBuf::from("foo"), ParityMode::Include);
        m.insert(PathBuf::from("foo/bar"), ParityMode::Exclude);
        let mut r = Resolver::new(m, ParityMode::Exclude);
        assert!(!r.covers_file(Path::new("foo/bar/zot")));
        assert!(r.covers_file(Path::new("foo/a/b/c")));
        assert!(r.covers_file(Path::new("foo/x")));
        assert!(!r.covers_file(Path::new("other/x")));
        assert!(!r.covers_file(Path::new("top")));
        let mut r2 = Resolver::new(HashMap::new(), ParityMode::Include);
        assert!(r2.covers_file(Path::new("top")));
    }
}
