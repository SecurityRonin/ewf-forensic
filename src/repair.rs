use crate::integrity::{adler32, EwfIntegrity, EwfIntegrityAnomaly, SECTION_DESCRIPTOR_SIZE};

pub struct EwfRepair {
    segments: Vec<Vec<u8>>,
}

pub struct RepairReport {
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

impl EwfRepair {
    pub fn new(data: Vec<u8>) -> Self {
        Self { segments: vec![data] }
    }

    pub fn from_segments(segments: Vec<Vec<u8>>) -> Self {
        Self { segments }
    }

    pub fn repair(mut self) -> RepairReport {
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
                    // Locate which segment contains this offset and apply the fix.
                    let mut abs = offset as usize;
                    for seg in &mut self.segments {
                        if abs < seg.len() {
                            let off = abs;
                            if off + SECTION_DESCRIPTOR_SIZE <= seg.len() {
                                let correct = adler32(&seg[off..off + 72]);
                                seg[off + 72..off + 76]
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

        RepairReport {
            segments: self.segments,
            repairs,
            cannot_repair,
        }
    }
}
