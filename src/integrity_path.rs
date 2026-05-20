use crate::integrity::{ComputedHashes, EwfIntegrity, EwfIntegrityAnomaly};
use memmap2::Mmap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Path-based, mmap-backed EWF integrity analyser.
///
/// Unlike [`EwfIntegrity`] (which takes `&[u8]` slices already in memory),
/// `EwfIntegrityPath` opens segment files and memory-maps them read-only.
/// The OS pages data on demand, so 500 GB evidence files are handled without
/// loading them into RAM.
///
/// # Segment auto-discovery
///
/// [`from_path`][EwfIntegrityPath::from_path] accepts the first segment
/// (`evidence.E01` / `evidence.e01`) and automatically discovers consecutive
/// siblings (`E02`, `E03`, … up to `EZZ`) in the same directory. Pass
/// [`from_paths`][EwfIntegrityPath::from_paths] to supply the segment list
/// explicitly.
pub struct EwfIntegrityPath {
    segment_paths: Vec<PathBuf>,
    expected_md5: Option<[u8; 16]>,
    expected_sha1: Option<[u8; 20]>,
    expected_sha256: Option<[u8; 32]>,
}

impl EwfIntegrityPath {
    /// Analyse a single segment or auto-discover a multi-segment image.
    ///
    /// If `path` has an extension matching the EWF numbered-segment pattern
    /// (`E01`/`e01`, `E02`/`e02`, …) this will look for consecutive siblings
    /// in the same directory and include them automatically.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let base = path.as_ref();
        Self {
            segment_paths: discover_segments(base),
            expected_md5: None,
            expected_sha1: None,
            expected_sha256: None,
        }
    }

    /// Analyse an explicit ordered list of segment paths.
    pub fn from_paths(paths: &[impl AsRef<Path>]) -> Self {
        Self {
            segment_paths: paths.iter().map(|p| p.as_ref().to_path_buf()).collect(),
            expected_md5: None,
            expected_sha1: None,
            expected_sha256: None,
        }
    }

    /// Supply an external chain-of-custody MD5 to compare against.
    pub fn with_expected_md5(mut self, hash: [u8; 16]) -> Self {
        self.expected_md5 = Some(hash);
        self
    }

    /// Supply an external chain-of-custody SHA-1 to compare against.
    pub fn with_expected_sha1(mut self, hash: [u8; 20]) -> Self {
        self.expected_sha1 = Some(hash);
        self
    }

    /// Supply an external chain-of-custody SHA-256 to compare against.
    /// Mismatch → `ExternalSha256Mismatch` (Critical).
    pub fn with_expected_sha256(mut self, hash: [u8; 32]) -> Self {
        self.expected_sha256 = Some(hash);
        self
    }

    /// Memory-map every segment and compute sector data hashes.
    ///
    /// Returns `Err` if any segment cannot be opened or mapped.
    /// Returns `Ok(None)` if the image is unparseable or is EWF v2.
    pub fn compute_hashes(&self) -> io::Result<Option<ComputedHashes>> {
        let mmaps = self
            .segment_paths
            .iter()
            .map(|p| {
                let file = File::open(p)?;
                unsafe { Mmap::map(&file) }
            })
            .collect::<io::Result<Vec<Mmap>>>()?;
        let seg_refs: Vec<&[u8]> = mmaps.iter().map(|m| m.as_ref()).collect();
        Ok(EwfIntegrity::from_segments(&seg_refs).compute_hashes())
    }

    /// Memory-map every segment and run the full integrity analyser.
    ///
    /// Returns `Err` if any segment file cannot be opened or mapped.
    pub fn analyse(&self) -> io::Result<Vec<EwfIntegrityAnomaly>> {
        let mmaps = self
            .segment_paths
            .iter()
            .map(|p| {
                let file = File::open(p)?;
                // SAFETY: we open the file read-only and do not modify it.
                // Concurrent truncation is not a concern for immutable evidence files.
                unsafe { Mmap::map(&file) }
            })
            .collect::<io::Result<Vec<Mmap>>>()?;

        let seg_refs: Vec<&[u8]> = mmaps.iter().map(|m| m.as_ref()).collect();

        let mut checker = EwfIntegrity::from_segments(&seg_refs);
        if let Some(h) = self.expected_md5 {
            checker = checker.with_expected_md5(h);
        }
        if let Some(h) = self.expected_sha1 {
            checker = checker.with_expected_sha1(h);
        }
        if let Some(h) = self.expected_sha256 {
            checker = checker.with_expected_sha256(h);
        }

        Ok(checker.analyse())
    }

    /// Memory-map every segment once and run analysis + hash computation in a
    /// single pass, avoiding duplicate I/O compared to calling [`analyse`] and
    /// [`compute_hashes`] separately.
    ///
    /// Returns `Err` if any segment file cannot be opened or mapped.
    /// If the image is too corrupted to compute hashes, a zeroed
    /// [`ComputedHashes`] is returned alongside the anomalies.
    pub fn analyse_and_compute_hashes(
        &self,
    ) -> io::Result<(Vec<EwfIntegrityAnomaly>, ComputedHashes)> {
        let mmaps = self
            .segment_paths
            .iter()
            .map(|p| {
                let file = File::open(p)?;
                // SAFETY: read-only mmap of an immutable evidence file.
                unsafe { Mmap::map(&file) }
            })
            .collect::<io::Result<Vec<Mmap>>>()?;

        let seg_refs: Vec<&[u8]> = mmaps.iter().map(|m| m.as_ref()).collect();

        let mut checker = EwfIntegrity::from_segments(&seg_refs);
        if let Some(h) = self.expected_md5 {
            checker = checker.with_expected_md5(h);
        }
        if let Some(h) = self.expected_sha1 {
            checker = checker.with_expected_sha1(h);
        }
        if let Some(h) = self.expected_sha256 {
            checker = checker.with_expected_sha256(h);
        }

        let anomalies = checker.analyse();
        let hashes = EwfIntegrity::from_segments(&seg_refs)
            .compute_hashes()
            .unwrap_or(ComputedHashes { md5: [0u8; 16], sha1: [0u8; 20], sha256: [0u8; 32] });

        Ok((anomalies, hashes))
    }
}

// ── Segment auto-discovery ────────────────────────────────────────────────────

/// Given the path to an E01 segment, return an ordered list of all discovered
/// sibling segments (E01, E02, … E09, E10, … EZZ).
///
/// If the path does not have a recognised numbered-extension, returns a
/// single-element vec containing the given path.
fn discover_segments(base: &Path) -> Vec<PathBuf> {
    let ext = match base.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return vec![base.to_path_buf()],
    };

    // Match E01 / e01 / Ex01 style (first segment is always *01)
    let (prefix_char, has_x, digits) = match parse_ewf_extension(ext) {
        Some(v) => v,
        None => return vec![base.to_path_buf()],
    };

    let stem = match base.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return vec![base.to_path_buf()],
    };
    let dir = base.parent().unwrap_or(Path::new("."));

    let mut segments = Vec::new();
    for n in 1u32.. {
        let ext_str = make_ewf_extension(prefix_char, has_x, digits, n);
        let candidate = dir.join(format!("{stem}.{ext_str}"));
        if candidate.exists() {
            segments.push(candidate);
        } else {
            break;
        }
        if n >= 999 {
            break;
        }
    }

    if segments.is_empty() {
        vec![base.to_path_buf()]
    } else {
        segments
    }
}

/// Parse an EWF extension like `E01`, `e01`, `Ex01`, `L01` into
/// `(prefix_char, has_x, digit_count)`.
fn parse_ewf_extension(ext: &str) -> Option<(char, bool, usize)> {
    let mut chars = ext.chars();
    let prefix = chars.next()?;
    if !prefix.is_ascii_alphabetic() {
        return None;
    }
    let rest: String = chars.collect();
    let has_x = rest.starts_with('x') || rest.starts_with('X');
    let rest = rest.trim_start_matches(|c| c == 'x' || c == 'X');
    if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
        Some((prefix, has_x, rest.len()))
    } else {
        None
    }
}

/// Reconstruct an EWF extension for segment number `n` (1-based).
/// `prefix_char` = 'E' or 'e', `has_x` = true for Ex01/Lx01 style.
fn make_ewf_extension(prefix: char, has_x: bool, digit_count: usize, n: u32) -> String {
    let width = digit_count.max(2);
    let x = if has_x { "x" } else { "" };
    format!("{}{}{:0width$}", prefix, x, n, width = width)
}
