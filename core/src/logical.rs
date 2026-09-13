//! EnCase **Logical** Evidence File (EWF-L01) — the file-entry tree.
//!
//! An L01 shares the EWF v1 container with an E01 and carries something
//! completely different: not disk sectors but a tree of file ENTRIES, selected
//! by the examiner at acquisition time. There is no partition table, no
//! filesystem and no unallocated space, so an L01 cannot be "mounted" the way a
//! disk image can — it is enumerated.
//!
//! The tree lives in an `ltree` section: a 48-byte header followed by a
//! UTF-16LE *text* body of tab-separated, newline-delimited categories
//! (`rec`, `perm`, `srce`, `sub`, `entry`).
//!
//! Reference: libyal, *Expert Witness Compression Format (EWF)*, "Ltree
//! section".

use crate::error::{EwfError, Result};
use safe_read::{le_u32, le_u64};

/// Size of the `ltree` section header in bytes.
pub const LTREE_HEADER_SIZE: usize = 48;

/// Header of an `ltree` section.
///
/// Carries its own integrity values, which is why this type exists rather than
/// the caller indexing bytes: an `ltree` that does not match its stored MD5 is
/// a damaged file tree, and on a logical acquisition the tree IS the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LtreeHeader {
    /// MD5 of the ltree data that follows the header.
    pub data_md5: [u8; 16],
    /// Size in bytes of the ltree data.
    pub data_size: u64,
    /// Adler-32 stored in the header, computed over the header with the
    /// checksum field itself zeroed.
    pub checksum: u32,
}

impl LtreeHeader {
    /// Parse an `ltree` header from the start of `buf`.
    ///
    /// # Errors
    /// [`EwfError::BufferTooShort`] when fewer than [`LTREE_HEADER_SIZE`] bytes
    /// are available.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < LTREE_HEADER_SIZE {
            return Err(EwfError::BufferTooShort {
                expected: LTREE_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let mut data_md5 = [0u8; 16];
        data_md5.copy_from_slice(&buf[0..16]);
        Ok(Self {
            data_md5,
            data_size: le_u64(buf, 16),
            checksum: le_u32(buf, 24),
        })
    }

    /// Whether the header's own Adler-32 checks out.
    ///
    /// The stored checksum covers the header bytes with the checksum field
    /// zeroed, so verification must zero the same four bytes rather than skip
    /// them — skipping shortens the buffer and changes the result.
    #[must_use]
    pub fn verify_checksum(&self, buf: &[u8]) -> bool {
        let Some(hdr) = buf.get(..LTREE_HEADER_SIZE) else {
            return false;
        };
        // Zero the checksum field rather than skipping it: skipping would
        // shorten the buffer and change the Adler-32 of everything after it.
        let mut probe = hdr.to_vec();
        probe[24..28].fill(0);
        crate::sections::adler32(&probe) == self.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a spec-shaped `ltree` header for `data`.
    ///
    /// TIER 3: hand-built from the libyal specification, not minted by EnCase.
    /// It pins our reading of the documented layout and nothing more; the
    /// real-world check is the env-gated test against an actual L01.
    fn ltree_header_for(data: &[u8]) -> Vec<u8> {
        use md5::{Digest as _, Md5};
        let mut h = vec![0u8; LTREE_HEADER_SIZE];
        h[0..16].copy_from_slice(&Md5::digest(data));
        h[16..24].copy_from_slice(&(data.len() as u64).to_le_bytes());
        let sum = crate::sections::adler32(&h);
        h[24..28].copy_from_slice(&sum.to_le_bytes());
        h
    }

    /// RED: the header must yield the integrity values that guard the tree.
    ///
    /// On a logical acquisition the entry tree IS the evidence — there is no
    /// filesystem to fall back on — so a tree that fails its stored MD5 is a
    /// damaged exhibit, not a cosmetic problem. Reading these values is what
    /// makes that detectable at all.
    #[test]
    fn ltree_header_yields_the_integrity_values() {
        let data = b"5\nrec\n";
        let h = ltree_header_for(data);

        let parsed = LtreeHeader::parse(&h).expect("a spec-shaped ltree header must parse");
        assert_eq!(parsed.data_size, data.len() as u64, "data size");
        use md5::{Digest as _, Md5};
        assert_eq!(
            parsed.data_md5,
            <[u8; 16]>::from(Md5::digest(data)),
            "the stored MD5 must be the MD5 of the data"
        );
        assert!(
            parsed.verify_checksum(&h),
            "and the header's own Adler-32 must verify"
        );
    }

    /// RED: a truncated header must be refused, never read past.
    #[test]
    fn ltree_header_refuses_a_short_buffer() {
        assert!(
            LtreeHeader::parse(&[0u8; LTREE_HEADER_SIZE - 1]).is_err(),
            "a short header must be refused rather than over-read"
        );
    }

    /// RED: a corrupted header must fail its checksum. Without this the
    /// verification could be a constant `true` and nothing would notice.
    #[test]
    fn ltree_header_detects_a_corrupted_header() {
        let data = b"5\nrec\n";
        let mut h = ltree_header_for(data);
        h[17] ^= 0xFF; // flip a bit in the declared size
        let parsed = LtreeHeader::parse(&h).expect("still structurally parseable");
        assert!(
            !parsed.verify_checksum(&h),
            "a corrupted header must fail its own checksum"
        );
    }
}
