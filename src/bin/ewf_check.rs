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
            eprintln!("error: {e}");
            process::exit(2);
        }
    };

    let visible: Vec<&EwfIntegrityAnomaly> = findings
        .iter()
        .filter(|a| severity_gte(a.severity(), &min_severity))
        .collect();

    if visible.is_empty() {
        println!("clean — 0 anomalies at or above {}", severity_label(&min_severity));
        process::exit(0);
    }

    println!("{} anomaly/anomalies found:\n", visible.len());
    for anomaly in &visible {
        let tag = match anomaly.severity() {
            Severity::Critical => "[CRITICAL]",
            Severity::Error => "[ERROR]   ",
            Severity::Warning => "[WARNING] ",
            Severity::Info => "[INFO]    ",
        };
        println!("{tag} {anomaly:?}");
    }

    process::exit(1);
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
