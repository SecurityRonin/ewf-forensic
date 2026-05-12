use std::fmt;

#[derive(Debug)]
pub enum EwfForensicError {
    TooShort { expected: usize, got: usize },
}

impl fmt::Display for EwfForensicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, got } => {
                write!(f, "data too short: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for EwfForensicError {}
