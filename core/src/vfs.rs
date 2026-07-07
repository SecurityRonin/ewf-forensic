//! `forensic-vfs` integration: `EwfReader` as an [`ImageSource`].
//!
//! An E01 image is a read-only, randomly-addressable byte stream — exactly the
//! `ImageSource` contract. `EwfReader` already exposes positioned `read_at(&self,
//! buf, offset)` + `total_size()`, so this is a thin delegation behind the `vfs`
//! feature (Phase 2 of the universal forensic VFS).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use forensic_vfs::{DynSource, ImageSource};

    use crate::EwfReader;

    const NPS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/nps-2010-emails.E01"
    );

    #[test]
    fn ewf_reader_is_an_image_source() {
        let reader = EwfReader::open(NPS).expect("open E01");
        let expected_len = reader.total_size();

        // The load-bearing claim: an EwfReader composes as a dyn ImageSource.
        let src: Arc<dyn ImageSource> = Arc::new(reader);
        assert_eq!(src.len(), expected_len);
        assert!(!src.is_empty());

        // Positioned read of the first sector returns bytes, no cursor.
        let mut buf = [0u8; 512];
        let n = src.read_at(0, &mut buf).expect("read_at");
        assert_eq!(n, 512);

        // A read fully past EOF yields 0 (the ImageSource short-read contract).
        assert_eq!(src.read_at(expected_len, &mut buf).expect("eof read"), 0);
    }

    #[test]
    fn subrange_windows_an_ewf_source() {
        // Proves the fleet composition seam: SubRange over a dyn EWF source.
        let reader = EwfReader::open(NPS).expect("open E01");
        let base: DynSource = Arc::new(reader);
        let sr = forensic_vfs::adapters::SubRange::new(base, 512, 1024);
        assert_eq!(sr.len(), 1024);
        let mut buf = [0u8; 1024];
        assert_eq!(sr.read_at(0, &mut buf).expect("read window"), 1024);
    }
}
