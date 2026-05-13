use crate::integrity::{adler32, EwfIntegrity, EwfIntegrityAnomaly, SECTION_DESCRIPTOR_SIZE};

/// Canonicalises EWF section descriptor Adler-32 CRCs in-memory.
///
/// # Forensic warning
///
/// **This operation alters evidence bytes.** Recomputing a CRC does not
/// restore the integrity of the underlying data — it hides the anomaly that
/// proved tampering. A canonicalised image will hash to a *different* value
/// than the original, breaking chain of custody.
///
/// Legitimate uses are narrow:
/// - Verifying that a tool-written image is internally self-consistent before
///   it is admitted as evidence (pre-submission check, not post-corruption fix).
/// - Generating reference images in a forensic lab, where the output is
///   immediately re-hashed and the original is retained alongside it.
///
/// If you are trying to "fix" a corrupt acquisition, stop. Preserve the
/// original. Document the anomaly. Escalate to the case analyst.
pub struct EwfDescriptorCanonicaliser {
    segments: Vec<Vec<u8>>,
}

pub struct CanonicalisationReport {
    pub segments: Vec<Vec<u8>>,
    pub repairs: Vec<Repaired>,
    pub cannot_repair: Vec<CannotRepair>,
}

#[derive(Debug, Clone)]
pub enum Repaired {
    SectionDescriptorCrc { offset: u64, section_type: String },
}

#[derive(Debug, Clone)]
pub enum CannotRepair {
    HashMismatch {
        computed: [u8; 16],
        stored: [u8; 16],
    },
}

impl EwfDescriptorCanonicaliser {
    pub fn new(data: Vec<u8>) -> Self {
        Self { segments: vec![data] }
    }

    pub fn from_segments(segments: Vec<Vec<u8>>) -> Self {
        Self { segments }
    }

    pub fn canonicalise(mut self) -> CanonicalisationReport {
        let mut repairs = Vec::new();
        let mut cannot_repair = Vec::new();

        let seg_refs: Vec<&[u8]> = self.segments.iter().map(|s| s.as_slice()).collect();
        let anomalies = EwfIntegrity::from_segments(&seg_refs).analyse();

        for anomaly in anomalies {
            match anomaly {
                EwfIntegrityAnomaly::SectionDescriptorCrcMismatch {
                    offset,
                    section_type,
                    ..
                } => {
                    let mut abs = offset as usize;
                    for seg in &mut self.segments {
                        if abs < seg.len() {
                            if abs + SECTION_DESCRIPTOR_SIZE <= seg.len() {
                                let correct = adler32(&seg[abs..abs + 72]);
                                seg[abs + 72..abs + 76]
                                    .copy_from_slice(&correct.to_le_bytes());
                                repairs.push(Repaired::SectionDescriptorCrc {
                                    offset,
                                    section_type,
                                });
                            }
                            break;
                        }
                        abs -= seg.len();
                    }
                }
                EwfIntegrityAnomaly::HashMismatch { computed, stored } => {
                    cannot_repair.push(CannotRepair::HashMismatch { computed, stored });
                }
                _ => {}
            }
        }

        CanonicalisationReport {
            segments: self.segments,
            repairs,
            cannot_repair,
        }
    }
}

// ── Backward-compatibility shim ───────────────────────────────────────────────

/// Legacy name. Use [`EwfDescriptorCanonicaliser`] instead.
///
/// # Forensic warning
///
/// See [`EwfDescriptorCanonicaliser`] for a full discussion of why in-memory
/// CRC patching is rarely the right response to a corrupt acquisition.
#[deprecated(
    since = "0.4.0",
    note = "Renamed to EwfDescriptorCanonicaliser; \
            see its doc comment for the forensic implications of CRC patching"
)]
pub struct EwfRepair {
    inner: EwfDescriptorCanonicaliser,
}

/// Report returned by the deprecated [`EwfRepair::repair`] method.
#[deprecated(since = "0.4.0", note = "Use CanonicalisationReport instead")]
pub struct RepairReport {
    pub data: Vec<u8>,
    pub segments: Vec<Vec<u8>>,
    pub repairs: Vec<Repaired>,
    pub cannot_repair: Vec<CannotRepair>,
}

#[allow(deprecated)]
impl EwfRepair {
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: EwfDescriptorCanonicaliser::new(data) }
    }

    pub fn from_segments(segments: Vec<Vec<u8>>) -> Self {
        Self { inner: EwfDescriptorCanonicaliser::from_segments(segments) }
    }

    pub fn repair(self) -> RepairReport {
        let r = self.inner.canonicalise();
        let data = r.segments.first().cloned().unwrap_or_default();
        RepairReport {
            data,
            segments: r.segments,
            repairs: r.repairs,
            cannot_repair: r.cannot_repair,
        }
    }
}
