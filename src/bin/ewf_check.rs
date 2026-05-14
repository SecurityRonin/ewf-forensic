use ewf_forensic::{EwfIntegrityAnomaly, EwfIntegrityPath, Severity};
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
    --help                    Show this help and exit.

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

    let mut min_severity = Severity::Info;
    let mut json_mode = false;
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

    let checker = if paths.len() == 1 {
        EwfIntegrityPath::from_path(&paths[0])
    } else {
        EwfIntegrityPath::from_paths(&paths)
    };

    let findings = match checker.analyse() {
        Ok(f) => f,
        Err(e) => {
            if json_mode {
                println!("{{\"error\": \"{}\"}}", json_escape(&e.to_string()));
            } else {
                eprintln!("error: {e}");
            }
            process::exit(2);
        }
    };

    let visible: Vec<&EwfIntegrityAnomaly> = findings
        .iter()
        .filter(|a| severity_gte(a.severity(), &min_severity))
        .collect();

    if json_mode {
        print_json(&visible, &min_severity);
    } else {
        print_text(&visible, &min_severity);
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

fn print_json(visible: &[&EwfIntegrityAnomaly], _min_severity: &Severity) {
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
    out.push_str("]\n}");
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
        EwfIntegrityAnomaly::ChunkSizeInvalid { .. } => "ChunkSizeInvalid",
        EwfIntegrityAnomaly::SectorCountMismatch { .. } => "SectorCountMismatch",
        EwfIntegrityAnomaly::BytesPerSectorInvalid { .. } => "BytesPerSectorInvalid",
        EwfIntegrityAnomaly::TableChunkCountMismatch { .. } => "TableChunkCountMismatch",
        EwfIntegrityAnomaly::TableEntryOutOfBounds { .. } => "TableEntryOutOfBounds",
        EwfIntegrityAnomaly::TableEntryOutsideSectorsRange { .. } => "TableEntryOutsideSectorsRange",
        EwfIntegrityAnomaly::SectionGapZero { .. } => "SectionGapZero",
        EwfIntegrityAnomaly::HashMismatch { .. } => "HashMismatch",
        EwfIntegrityAnomaly::HashSectionMissing => "HashSectionMissing",
        EwfIntegrityAnomaly::SegmentOutOfOrder { .. } => "SegmentOutOfOrder",
        EwfIntegrityAnomaly::DigestSha1Mismatch { .. } => "DigestSha1Mismatch",
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
        EwfIntegrityAnomaly::Ewf2BytesPerSectorInvalid { .. } => "Ewf2BytesPerSectorInvalid",
        EwfIntegrityAnomaly::Ewf2ChunkSizeInvalid { .. } => "Ewf2ChunkSizeInvalid",
        EwfIntegrityAnomaly::Ewf2SectorCountZero => "Ewf2SectorCountZero",
        EwfIntegrityAnomaly::ChunkChecksumMismatch { .. } => "ChunkChecksumMismatch",
        EwfIntegrityAnomaly::ChunkDecompressionError { .. } => "ChunkDecompressionError",
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
