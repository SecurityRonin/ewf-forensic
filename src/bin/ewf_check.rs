use ewf_forensic::{ComputedHashes, EwfIntegrityAnomaly, EwfIntegrityPath, Severity};
use std::path::PathBuf;
use std::process;

const HELP: &str = "\
ewf-check — forensic integrity analysis for EWF / E01 images

USAGE
    ewf-check [OPTIONS] <segment>...

ARGUMENTS
    <segment>...    One or more segment paths (evidence.E01, evidence.E02, …).
                    When a single .E01 path is given, consecutive siblings are
                    discovered automatically.

OPTIONS
    --min-severity=<level>    Only report anomalies at or above this severity.
                              Levels: info, warning, error, critical [default: info]
    --json                    Emit machine-readable JSON instead of human text.
    --hash-md5=<hex>          Compare computed MD5 against this hex string (chain-of-custody).
    --hash-sha1=<hex>         Compare computed SHA-1 against this hex string.
    --hash-sha256=<hex>       Compare computed SHA-256 against this hex string.
    --print-hashes            Compute and print MD5, SHA-1, and SHA-256 of all sector data.
                              Combined with --json: adds a \"hashes\" object to the JSON output.
    --help                    Show this help and exit.
    --version                 Print version and exit.

EXIT CODES
    0   Clean — no anomalies at or above --min-severity
    1   Anomalies found
    2   Usage error or I/O failure
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("{HELP}");
        process::exit(2);
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        process::exit(0);
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("ewf-check {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let mut min_severity = Severity::Info;
    let mut json_mode = false;
    let mut print_hashes = false;
    let mut hash_md5: Option<[u8; 16]> = None;
    let mut hash_sha1: Option<[u8; 20]> = None;
    let mut hash_sha256: Option<[u8; 32]> = None;
    let mut paths: Vec<PathBuf> = Vec::new();

    for arg in &args {
        if let Some(val) = arg.strip_prefix("--min-severity=") {
            min_severity = match val {
                "info" | "Info" => Severity::Info,
                "warning" | "Warning" => Severity::Warning,
                "error" | "Error" => Severity::Error,
                "critical" | "Critical" => Severity::Critical,
                other => {
                    eprintln!("error: unknown severity level '{other}'; expected info/warning/error/critical");
                    process::exit(2);
                }
            };
        } else if arg == "--json" {
            json_mode = true;
        } else if arg == "--print-hashes" {
            print_hashes = true;
        } else if let Some(hex) = arg.strip_prefix("--hash-md5=") {
            hash_md5 = Some(parse_hex_fixed::<16>(hex, "--hash-md5"));
        } else if let Some(hex) = arg.strip_prefix("--hash-sha1=") {
            hash_sha1 = Some(parse_hex_fixed::<20>(hex, "--hash-sha1"));
        } else if let Some(hex) = arg.strip_prefix("--hash-sha256=") {
            hash_sha256 = Some(parse_hex_fixed::<32>(hex, "--hash-sha256"));
        } else if arg.starts_with('-') {
            eprintln!("error: unknown option '{arg}'");
            eprintln!("Run 'ewf-check --help' for usage.");
            process::exit(2);
        } else {
            paths.push(PathBuf::from(arg));
        }
    }

    if paths.is_empty() {
        eprintln!("error: no segment paths provided");
        eprintln!("Run 'ewf-check --help' for usage.");
        process::exit(2);
    }

    let mut checker = if paths.len() == 1 {
        EwfIntegrityPath::from_path(&paths[0])
    } else {
        EwfIntegrityPath::from_paths(&paths)
    };
    if let Some(h) = hash_md5 { checker = checker.with_expected_md5(h); }
    if let Some(h) = hash_sha1 { checker = checker.with_expected_sha1(h); }
    if let Some(h) = hash_sha256 { checker = checker.with_expected_sha256(h); }

    let (findings, computed) = match (checker.analyse(), print_hashes) {
        (Err(e), _) => {
            if json_mode {
                println!("{{\"error\": \"{}\"}}", json_escape(&e.to_string()));
            } else {
                eprintln!("error: {e}");
            }
            process::exit(2);
        }
        (Ok(f), true) => {
            let c = if paths.len() == 1 {
                EwfIntegrityPath::from_path(&paths[0]).compute_hashes()
            } else {
                EwfIntegrityPath::from_paths(&paths).compute_hashes()
            };
            let hashes = match c {
                Err(e) => {
                    if json_mode {
                        println!("{{\"error\": \"{}\"}}", json_escape(&e.to_string()));
                    } else {
                        eprintln!("error: {e}");
                    }
                    process::exit(2);
                }
                Ok(h) => h,
            };
            (f, hashes)
        }
        (Ok(f), false) => (f, None),
    };

    let visible: Vec<&EwfIntegrityAnomaly> = findings
        .iter()
        .filter(|a| severity_gte(a.severity(), &min_severity))
        .collect();

    if json_mode {
        print_json(&visible, &min_severity, computed.as_ref());
    } else {
        print_text(&visible, &min_severity);
        if let Some(ref h) = computed {
            println!();
            println!("MD5:    {}", hex_string(&h.md5));
            println!("SHA-1:  {}", hex_string(&h.sha1));
            println!("SHA-256: {}", hex_string(&h.sha256));
        }
    }

    process::exit(if visible.is_empty() { 0 } else { 1 });
}

fn print_text(visible: &[&EwfIntegrityAnomaly], min_severity: &Severity) {
    if visible.is_empty() {
        println!("clean — 0 anomalies at or above {}", severity_label(min_severity));
        return;
    }
    println!("{} anomaly/anomalies found:\n", visible.len());
    for anomaly in visible {
        let tag = match anomaly.severity() {
            Severity::Critical => "[CRITICAL]",
            Severity::Error => "[ERROR]   ",
            Severity::Warning => "[WARNING] ",
            Severity::Info => "[INFO]    ",
        };
        println!("{tag} {anomaly}");
    }
}

fn print_json(visible: &[&EwfIntegrityAnomaly], _min_severity: &Severity, hashes: Option<&ComputedHashes>) {
    let clean = visible.is_empty();
    let count = visible.len();
    let mut out = format!(
        "{{\n  \"clean\": {},\n  \"anomaly_count\": {},\n  \"anomalies\": [",
        clean, count
    );
    for (i, anomaly) in visible.iter().enumerate() {
        let sep = if i == 0 { "\n" } else { ",\n" };
        out.push_str(&format!(
            "{}    {{\"severity\": \"{}\", \"kind\": \"{}\", \"message\": \"{}\"}}",
            sep,
            severity_label(&anomaly.severity()),
            anomaly_kind(anomaly),
            json_escape(&anomaly.to_string()),
        ));
    }
    if !visible.is_empty() {
        out.push_str("\n  ");
    }
    out.push_str("]");
    if let Some(h) = hashes {
        out.push_str(&format!(
            ",\n  \"hashes\": {{\n    \"md5\": \"{}\",\n    \"sha1\": \"{}\",\n    \"sha256\": \"{}\"\n  }}",
            hex_string(&h.md5),
            hex_string(&h.sha1),
            hex_string(&h.sha256),
        ));
    }
    out.push_str("\n}");
    println!("{out}");
}

fn anomaly_kind(a: &EwfIntegrityAnomaly) -> &'static str {
    match a {
        EwfIntegrityAnomaly::InvalidSignature => "InvalidSignature",
        EwfIntegrityAnomaly::SegmentNumberZero => "SegmentNumberZero",
        EwfIntegrityAnomaly::SectionDescriptorCrcMismatch { .. } => "SectionDescriptorCrcMismatch",
        EwfIntegrityAnomaly::SectionChainBroken { .. } => "SectionChainBroken",
        EwfIntegrityAnomaly::SectionGapNonZero { .. } => "SectionGapNonZero",
        EwfIntegrityAnomaly::VolumeSectionMissing => "VolumeSectionMissing",
        EwfIntegrityAnomaly::UnknownSectionType { .. } => "UnknownSectionType",
        EwfIntegrityAnomaly::DoneSectionMissing => "DoneSectionMissing",
        EwfIntegrityAnomaly::SectorsSectionMissing => "SectorsSectionMissing",
        EwfIntegrityAnomaly::TableSectionMissing => "TableSectionMissing",
        EwfIntegrityAnomaly::ChunkSizeInvalid { .. } => "ChunkSizeInvalid",
        EwfIntegrityAnomaly::SectorCountMismatch { .. } => "SectorCountMismatch",
        EwfIntegrityAnomaly::BytesPerSectorInvalid { .. } => "BytesPerSectorInvalid",
        EwfIntegrityAnomaly::TableChunkCountMismatch { .. } => "TableChunkCountMismatch",
        EwfIntegrityAnomaly::TableHeaderAdler32Mismatch { .. } => "TableHeaderAdler32Mismatch",
        EwfIntegrityAnomaly::TableEntryOutOfBounds { .. } => "TableEntryOutOfBounds",
        EwfIntegrityAnomaly::TableEntryOutsideSectorsRange { .. } => "TableEntryOutsideSectorsRange",
        EwfIntegrityAnomaly::SectionGapZero { .. } => "SectionGapZero",
        EwfIntegrityAnomaly::HashMismatch { .. } => "HashMismatch",
        EwfIntegrityAnomaly::HashSectionMissing => "HashSectionMissing",
        EwfIntegrityAnomaly::Table2Mismatch { .. } => "Table2Mismatch",
        EwfIntegrityAnomaly::BadSectorsPresent { .. } => "BadSectorsPresent",
        EwfIntegrityAnomaly::SegmentOutOfOrder { .. } => "SegmentOutOfOrder",
        EwfIntegrityAnomaly::DigestSha1Mismatch { .. } => "DigestSha1Mismatch",
        EwfIntegrityAnomaly::DigestSha256Mismatch { .. } => "DigestSha256Mismatch",
        EwfIntegrityAnomaly::ExternalMd5Mismatch { .. } => "ExternalMd5Mismatch",
        EwfIntegrityAnomaly::ExternalSha1Mismatch { .. } => "ExternalSha1Mismatch",
        EwfIntegrityAnomaly::ExternalSha256Mismatch { .. } => "ExternalSha256Mismatch",
        EwfIntegrityAnomaly::Ewf2SectionDataHashMismatch { .. } => "Ewf2SectionDataHashMismatch",
        EwfIntegrityAnomaly::Ewf2EncryptedSection { .. } => "Ewf2EncryptedSection",
        EwfIntegrityAnomaly::Ewf2HashSectionMissing => "Ewf2HashSectionMissing",
        EwfIntegrityAnomaly::VolumeBodyCrcMismatch { .. } => "VolumeBodyCrcMismatch",
        EwfIntegrityAnomaly::MediaTypeUnknown { .. } => "MediaTypeUnknown",
        EwfIntegrityAnomaly::SetIdentifierMismatch { .. } => "SetIdentifierMismatch",
        EwfIntegrityAnomaly::Ewf2MediaInfoMissing => "Ewf2MediaInfoMissing",
        EwfIntegrityAnomaly::Ewf2ChunkTableChecksumMismatch { .. } => "Ewf2ChunkTableChecksumMismatch",
        EwfIntegrityAnomaly::ChunkChecksumMismatch { .. } => "ChunkChecksumMismatch",
        EwfIntegrityAnomaly::ChunkDecompressionError { .. } => "ChunkDecompressionError",
        EwfIntegrityAnomaly::Ewf2MediaInfoParseFailed => "Ewf2MediaInfoParseFailed",
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn parse_hex_fixed<const N: usize>(hex: &str, flag: &str) -> [u8; N] {
    if hex.len() != N * 2 {
        eprintln!(
            "error: {flag} expects exactly {} hex characters (got {})",
            N * 2,
            hex.len()
        );
        process::exit(2);
    }
    let mut out = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).unwrap_or("??");
        match u8::from_str_radix(s, 16) {
            Ok(b) => out[i] = b,
            Err(_) => {
                eprintln!("error: {flag} contains invalid hex character in '{s}'");
                process::exit(2);
            }
        }
    }
    out
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn severity_gte(a: Severity, min: &Severity) -> bool {
    severity_rank(&a) >= severity_rank(min)
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    }
}
