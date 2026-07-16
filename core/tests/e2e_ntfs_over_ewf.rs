//! End-to-end forensic-VFS composition proof (Phase 2, Step 4).
//!
//! Wires the whole stack over a REAL NTFS-in-E01, proving the `forensic-vfs`
//! contracts compose real fleet readers with no glue beyond the traits:
//!
//! ```text
//!   EwfReader (E01)  ─impl ImageSource→  Arc<dyn ImageSource>
//!                    ─SourceCursor─────→  Read + Seek view
//!   NtfsFs::open(..) ─impl FileSystem→   Arc<dyn FileSystem>
//!                    ─lookup/read_at──→  file bytes
//! ```
//!
//! The fixture `ntfs_sample.E01` was minted with `ewfacquire` from the
//! TSK-validated `SampleTinyNtfsVolume` `partition.dd` (see
//! `tests/data/README`), so the file content oracle is The Sleuth Kit's
//! `istat`/`icat`: `file1.txt` = MFT record 37, 408 bytes, begins "Just some
//! bogus". This is a local-only proof (path dev-deps on the vfs branches).

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ewf::EwfReader;
use forensic_vfs::adapters::SourceCursor;
use forensic_vfs::{DynSource, FileId, FileSystem, ImageSource, StreamId};
use ntfs_core::NtfsFs;

const E01: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/ntfs_sample.E01");

#[test]
fn ewf_container_feeds_ntfs_filesystem_end_to_end() {
    // 1. E01 container decoded → dyn ImageSource (the source side, Step 3).
    let reader = EwfReader::open(E01).expect("open ntfs_sample.E01");
    let src: DynSource = Arc::new(reader);
    let len = src.len();
    assert_eq!(len, 7_340_032, "the acquired 7 MiB NTFS volume");

    // 2. dyn ImageSource → Read+Seek view over the whole bare NTFS volume.
    let cursor = SourceCursor::new(src, 0, len);

    // 3. NTFS mounted over the cursor → dyn FileSystem (the FS side, Step 2).
    let fs: Arc<dyn FileSystem> = Arc::new(NtfsFs::open(cursor).expect("mount NTFS over E01"));

    // 4. Read a known file through the ENTIRE stack; TSK is the oracle.
    let id = fs
        .lookup(fs.root(), b"file1.txt")
        .expect("lookup")
        .expect("file1.txt present");
    assert_eq!(id, FileId::NtfsRef { entry: 37, seq: 1 });

    let mut buf = [0u8; 512];
    let n = fs
        .read_at(id, StreamId::Default, 0, &mut buf)
        .expect("read file1.txt through the stack");
    assert_eq!(n, 408, "istat: file1.txt $DATA size 408");
    assert_eq!(&buf[..15], b"Just some bogus", "icat content, via E01→NTFS");
}
