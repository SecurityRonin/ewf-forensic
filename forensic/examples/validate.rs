use ewf_forensic::{EwfIntegrity, Severity};
use std::process;

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: validate <image.E01> [image2.E01 ...]");
        process::exit(1);
    }

    let mut any_error = false;

    for path in &paths {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[SKIP] {path}: {e}");
                continue;
            }
        };

        let findings = EwfIntegrity::new(&data).analyse();
        let size_kb = data.len() / 1024;

        if findings.is_empty() {
            println!("[CLEAN]  {path}  ({size_kb} KB) — no anomalies");
        } else {
            for a in &findings {
                let tag = match a.severity() {
                    Severity::Critical => "[CRIT ]",
                    Severity::High => "[HIGH ]",
                    Severity::Medium => "[MED  ]",
                    Severity::Low => "[LOW  ]",
                    Severity::Info => "[INFO ]",
                    _ => "[?    ]",
                };
                println!("{tag}  {path}  ({size_kb} KB)  {a:?}");
            }
            let has_error = findings
                .iter()
                .any(|a| matches!(a.severity(), Severity::Critical | Severity::High));
            if has_error {
                any_error = true;
            }
        }
    }

    if any_error {
        process::exit(1);
    }
}
