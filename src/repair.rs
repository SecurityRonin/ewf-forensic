use crate::integrity::{adler32, EwfIntegrity, EwfIntegrityAnomaly, SECTION_DESCRIPTOR_SIZE};

pub struct EwfRepair {
    data: Vec<u8>,
}

pub struct RepairReport {
    pub data: Vec<u8>,
    pub repairs: Vec<Repaired>,
    pub cannot_repair: Vec<CannotRepair>,
}

#[derive(Debug, Clone)]
pub enum Repaired {
    SectionDescriptorCrc { offset: u64, section_type: String },
}

#[derive(Debug, Clone)]
pub enum CannotRepair {
    HashMismatch { computed: [u8; 16], stored: [u8; 16] },
}

impl EwfRepair {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn repair(mut self) -> RepairReport {
        let mut repairs = Vec::new();
        let mut cannot_repair = Vec::new();

        let anomalies = EwfIntegrity::new(&self.data).analyse();

        for anomaly in anomalies {
            match anomaly {
                EwfIntegrityAnomaly::SectionDescriptorCrcMismatch {
                    offset,
                    section_type,
                    ..
                } => {
                    let off = offset as usize;
                    if off + SECTION_DESCRIPTOR_SIZE <= self.data.len() {
                        let correct = adler32(&self.data[off..off + 72]);
                        self.data[off + 72..off + 76].copy_from_slice(&correct.to_le_bytes());
                        repairs.push(Repaired::SectionDescriptorCrc {
                            offset,
                            section_type,
                        });
                    }
                }
                EwfIntegrityAnomaly::HashMismatch { computed, stored } => {
                    cannot_repair.push(CannotRepair::HashMismatch { computed, stored });
                }
                _ => {}
            }
        }

        RepairReport {
            data: self.data,
            repairs,
            cannot_repair,
        }
    }
}
