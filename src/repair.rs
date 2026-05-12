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

    pub fn repair(self) -> RepairReport {
        todo!()
    }
}
