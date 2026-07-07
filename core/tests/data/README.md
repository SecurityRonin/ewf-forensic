
#### ntfs_sample.E01

- **Source:** minted with `ewfacquire 20231119` from `SampleTinyNtfsVolume/partition.dd`
  (Joakim Schicht's `LogFileParser` sample, MIT), which lives TSK-validated in
  `ntfs-forensic/tests/data/SampleTinyNtfsVolume.zip`.
- **Command:** `ewfacquire -u -t ntfs_sample -f encase6 -c deflate:best -S 4GiB partition.dd`
- **Contents:** a bare 7,340,032-byte NTFS volume (OEM id `NTFS`); MD5 over the
  acquired data `e4e9578a9c8bf6c6b375a80c630196a4`.
- **Use case:** `tests/e2e_ntfs_over_ewf.rs` — the Phase-2 end-to-end VFS proof
  (E01 → ImageSource → SourceCursor → NtfsFs → FileSystem). Oracle: TSK `istat`/`icat`
  (`file1.txt` = record 37, 408 bytes, "Just some bogus…").
