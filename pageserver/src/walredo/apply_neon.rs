use anyhow::Context;
use byteorder::{ByteOrder, LittleEndian};
use bytes::BytesMut;
use pageserver_api::key::Key;
use pageserver_api::reltag::SlruKind;
use postgres_ffi::v14::nonrelfile_utils::{
    mx_offset_to_flags_bitshift, mx_offset_to_flags_offset, mx_offset_to_member_offset,
    transaction_id_set_status,
};
use postgres_ffi::{BLCKSZ, MultiXactId, pg_constants};
use postgres_ffi_types::forknum::VISIBILITYMAP_FORKNUM;
use tracing::*;
use utils::lsn::Lsn;
use wal_decoder::models::record::NeonWalRecord;

/// The multixact id after `mid`: like Postgres, skip InvalidMultiXactId (0) on wraparound.
pub(crate) fn next_multixact_id(mid: MultiXactId) -> MultiXactId {
    match mid.wrapping_add(1) {
        0 => pg_constants::FIRST_MULTIXACT_ID,
        next => next,
    }
}

/// The byte offset of `mid`'s entry when it lies on multixact-offsets page
/// (`segno`, `blknum`), else None.
fn offsets_entry_on_page(mid: MultiXactId, segno: u32, blknum: u32) -> Option<usize> {
    let pageno = mid / pg_constants::MULTIXACT_OFFSETS_PER_PAGE as u32;
    let entryno = mid % pg_constants::MULTIXACT_OFFSETS_PER_PAGE as u32;
    (pageno / pg_constants::SLRU_PAGES_PER_SEGMENT == segno
        && pageno % pg_constants::SLRU_PAGES_PER_SEGMENT == blknum)
        .then_some((entryno * 4) as usize)
}

/// Can this request be served by neon redo functions
/// or we need to pass it to wal-redo postgres process?
pub(crate) fn can_apply_in_neon(rec: &NeonWalRecord) -> bool {
    // Currently, we don't have bespoken Rust code to replay any
    // Postgres WAL records. But everything else is handled in neon.
    #[allow(clippy::match_like_matches_macro)]
    match rec {
        NeonWalRecord::Postgres {
            will_init: _,
            rec: _,
        } => false,
        _ => true,
    }
}

pub(crate) fn apply_in_neon(
    record: &NeonWalRecord,
    lsn: Lsn,
    key: Key,
    page: &mut BytesMut,
) -> Result<(), anyhow::Error> {
    match record {
        NeonWalRecord::Postgres {
            will_init: _,
            rec: _,
        } => {
            anyhow::bail!("tried to pass postgres wal record to neon WAL redo");
        }
        //
        // Code copied from PostgreSQL `visibilitymap_prepare_truncate` function in `visibilitymap.c`
        //
        NeonWalRecord::TruncateVisibilityMap {
            trunc_byte,
            trunc_offs,
        } => {
            // sanity check that this is modifying the correct relation
            let (rel, _) = key.to_rel_block().context("invalid record")?;
            assert!(
                rel.forknum == VISIBILITYMAP_FORKNUM,
                "TruncateVisibilityMap record on unexpected rel {rel}"
            );
            let map = &mut page[pg_constants::MAXALIGN_SIZE_OF_PAGE_HEADER_DATA..];
            map[*trunc_byte + 1..].fill(0u8);
            /*----
             * Mask out the unwanted bits of the last remaining byte.
             *
             * ((1 << 0) - 1) = 00000000
             * ((1 << 1) - 1) = 00000001
             * ...
             * ((1 << 6) - 1) = 00111111
             * ((1 << 7) - 1) = 01111111
             *----
             */
            map[*trunc_byte] &= (1 << *trunc_offs) - 1;
        }
        NeonWalRecord::ClearVisibilityMapFlags {
            new_heap_blkno,
            old_heap_blkno,
            flags,
        } => {
            // sanity check that this is modifying the correct relation
            let (rel, blknum) = key.to_rel_block().context("invalid record")?;
            assert!(
                rel.forknum == VISIBILITYMAP_FORKNUM,
                "ClearVisibilityMapFlags record on unexpected rel {rel}"
            );
            if let Some(heap_blkno) = *new_heap_blkno {
                // Calculate the VM block and offset that corresponds to the heap block.
                let map_block = pg_constants::HEAPBLK_TO_MAPBLOCK(heap_blkno);
                let map_byte = pg_constants::HEAPBLK_TO_MAPBYTE(heap_blkno);
                let map_offset = pg_constants::HEAPBLK_TO_OFFSET(heap_blkno);

                // Check that we're modifying the correct VM block.
                assert!(map_block == blknum);

                // equivalent to PageGetContents(page)
                let map = &mut page[pg_constants::MAXALIGN_SIZE_OF_PAGE_HEADER_DATA..];

                map[map_byte as usize] &= !(flags << map_offset);
                // The page should never be empty, but we're checking it anyway as a precaution, so that if it is empty for some reason anyway, we don't make matters worse by setting the LSN on it.
                if !postgres_ffi::page_is_new(page) {
                    postgres_ffi::page_set_lsn(page, lsn);
                }
            }

            // Repeat for 'old_heap_blkno', if any
            if let Some(heap_blkno) = *old_heap_blkno {
                let map_block = pg_constants::HEAPBLK_TO_MAPBLOCK(heap_blkno);
                let map_byte = pg_constants::HEAPBLK_TO_MAPBYTE(heap_blkno);
                let map_offset = pg_constants::HEAPBLK_TO_OFFSET(heap_blkno);

                assert!(map_block == blknum);

                let map = &mut page[pg_constants::MAXALIGN_SIZE_OF_PAGE_HEADER_DATA..];

                map[map_byte as usize] &= !(flags << map_offset);
                // The page should never be empty, but we're checking it anyway as a precaution, so that if it is empty for some reason anyway, we don't make matters worse by setting the LSN on it.
                if !postgres_ffi::page_is_new(page) {
                    postgres_ffi::page_set_lsn(page, lsn);
                }
            }
        }
        // Non-relational WAL records are handled here, with custom code that has the
        // same effects as the corresponding Postgres WAL redo function.
        NeonWalRecord::ClogSetCommitted { xids, timestamp } => {
            let (slru_kind, segno, blknum) = key.to_slru_block().context("invalid record")?;
            assert_eq!(
                slru_kind,
                SlruKind::Clog,
                "ClogSetCommitted record with unexpected key {key}"
            );
            for &xid in xids {
                let pageno = xid / pg_constants::CLOG_XACTS_PER_PAGE;
                let expected_segno = pageno / pg_constants::SLRU_PAGES_PER_SEGMENT;
                let expected_blknum = pageno % pg_constants::SLRU_PAGES_PER_SEGMENT;

                // Check that we're modifying the correct CLOG block.
                assert!(
                    segno == expected_segno,
                    "ClogSetCommitted record for XID {xid} with unexpected key {key}"
                );
                assert!(
                    blknum == expected_blknum,
                    "ClogSetCommitted record for XID {xid} with unexpected key {key}"
                );

                transaction_id_set_status(xid, pg_constants::TRANSACTION_STATUS_COMMITTED, page);
            }

            // Append the timestamp
            if page.len() == BLCKSZ as usize + 8 {
                page.truncate(BLCKSZ as usize);
            }
            if page.len() == BLCKSZ as usize {
                page.extend_from_slice(&timestamp.to_be_bytes());
            } else {
                warn!(
                    "CLOG blk {} in seg {} has invalid size {}",
                    blknum,
                    segno,
                    page.len()
                );
            }
        }
        NeonWalRecord::ClogSetAborted { xids } => {
            let (slru_kind, segno, blknum) = key.to_slru_block().context("invalid record")?;
            assert_eq!(
                slru_kind,
                SlruKind::Clog,
                "ClogSetAborted record with unexpected key {key}"
            );
            for &xid in xids {
                let pageno = xid / pg_constants::CLOG_XACTS_PER_PAGE;
                let expected_segno = pageno / pg_constants::SLRU_PAGES_PER_SEGMENT;
                let expected_blknum = pageno % pg_constants::SLRU_PAGES_PER_SEGMENT;

                // Check that we're modifying the correct CLOG block.
                assert!(
                    segno == expected_segno,
                    "ClogSetAborted record for XID {xid} with unexpected key {key}"
                );
                assert!(
                    blknum == expected_blknum,
                    "ClogSetAborted record for XID {xid} with unexpected key {key}"
                );

                transaction_id_set_status(xid, pg_constants::TRANSACTION_STATUS_ABORTED, page);
            }
        }
        NeonWalRecord::MultixactOffsetCreate { mid, moff } => {
            let (slru_kind, segno, blknum) = key.to_slru_block().context("invalid record")?;
            assert_eq!(
                slru_kind,
                SlruKind::MultiXactOffsets,
                "MultixactOffsetCreate record with unexpected key {key}"
            );
            // Compute the block and offset to modify.
            // See RecordNewMultiXact in PostgreSQL sources.
            let pageno = mid / pg_constants::MULTIXACT_OFFSETS_PER_PAGE as u32;
            let entryno = mid % pg_constants::MULTIXACT_OFFSETS_PER_PAGE as u32;
            let offset = (entryno * 4) as usize;

            // Check that we're modifying the correct multixact-offsets block.
            let expected_segno = pageno / pg_constants::SLRU_PAGES_PER_SEGMENT;
            let expected_blknum = pageno % pg_constants::SLRU_PAGES_PER_SEGMENT;
            assert!(
                segno == expected_segno,
                "MultiXactOffsetsCreate record for multi-xid {mid} with unexpected key {key}"
            );
            assert!(
                blknum == expected_blknum,
                "MultiXactOffsetsCreate record for multi-xid {mid} with unexpected key {key}"
            );

            LittleEndian::write_u32(&mut page[offset..offset + 4], *moff);
        }
        NeonWalRecord::MultixactMembersCreate { moff, members } => {
            let (slru_kind, segno, blknum) = key.to_slru_block().context("invalid record")?;
            assert_eq!(
                slru_kind,
                SlruKind::MultiXactMembers,
                "MultixactMembersCreate record with unexpected key {key}"
            );
            for (i, member) in members.iter().enumerate() {
                // Member offsets wrap around at 2^32 (walingest splits a record there).
                let offset = moff.wrapping_add(i as u32);

                // Compute the block and offset to modify.
                // See RecordNewMultiXact in PostgreSQL sources.
                let pageno = offset / pg_constants::MULTIXACT_MEMBERS_PER_PAGE as u32;
                let memberoff = mx_offset_to_member_offset(offset);
                let flagsoff = mx_offset_to_flags_offset(offset);
                let bshift = mx_offset_to_flags_bitshift(offset);

                // Check that we're modifying the correct multixact-members block.
                let expected_segno = pageno / pg_constants::SLRU_PAGES_PER_SEGMENT;
                let expected_blknum = pageno % pg_constants::SLRU_PAGES_PER_SEGMENT;
                assert!(
                    segno == expected_segno,
                    "MultiXactMembersCreate record for offset {moff} with unexpected key {key}"
                );
                assert!(
                    blknum == expected_blknum,
                    "MultiXactMembersCreate record for offset {moff} with unexpected key {key}"
                );

                let mut flagsval = LittleEndian::read_u32(&page[flagsoff..flagsoff + 4]);
                flagsval &= !(((1 << pg_constants::MXACT_MEMBER_BITS_PER_XACT) - 1) << bshift);
                flagsval |= member.status << bshift;
                LittleEndian::write_u32(&mut page[flagsoff..flagsoff + 4], flagsval);
                LittleEndian::write_u32(&mut page[memberoff..memberoff + 4], member.xid);
            }
        }
        NeonWalRecord::MultixactOffsetCreateWithNext {
            mid,
            moff,
            next_moff,
        } => {
            let (slru_kind, segno, blknum) = key.to_slru_block().context("invalid record")?;
            assert_eq!(
                slru_kind,
                SlruKind::MultiXactOffsets,
                "MultixactOffsetCreateWithNext record with unexpected key {key}"
            );
            // See RecordNewMultiXact in PostgreSQL sources. The record is stored on the
            // page of each of the two entries; write the ones that are on this page.
            let next = next_multixact_id(*mid);
            let mid_offset = offsets_entry_on_page(*mid, segno, blknum);
            let next_offset = offsets_entry_on_page(next, segno, blknum);
            assert!(
                mid_offset.is_some() || next_offset.is_some(),
                "MultixactOffsetCreateWithNext record for multi-xid {mid} with unexpected key {key}"
            );
            if let Some(offset) = mid_offset {
                LittleEndian::write_u32(&mut page[offset..offset + 4], *moff);
            }
            // The next multixact's own record may have come first (concurrent creation);
            // then its entry is already set, to the same value.
            let next_unset = next_offset
                .filter(|&offset| LittleEndian::read_u32(&page[offset..offset + 4]) == 0);
            if let Some(offset) = next_unset {
                LittleEndian::write_u32(&mut page[offset..offset + 4], *next_moff);
            }
        }
        NeonWalRecord::AuxFile { .. } => {
            // No-op: this record will never be created in aux v2.
            warn!("AuxFile record should not be created in aux v2");
        }
        #[cfg(feature = "testing")]
        NeonWalRecord::Test {
            append,
            clear,
            will_init,
            only_if,
        } => {
            use bytes::BufMut;
            if *will_init {
                assert!(*clear, "init record must be clear to ensure correctness");
                assert!(
                    page.is_empty(),
                    "init record must be the first entry to ensure correctness"
                );
            }
            if *clear {
                page.clear();
            }
            if let Some(only_if) = only_if {
                if page != only_if.as_bytes() {
                    return Err(anyhow::anyhow!(
                        "the current image does not match the expected image, cannot append"
                    ));
                }
            }
            page.put_slice(append.as_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pageserver_api::key::slru_block_to_key;

    use super::*;

    const OFFSETS_PER_PAGE: u32 = pg_constants::MULTIXACT_OFFSETS_PER_PAGE as u32;

    fn offsets_key(pageno: u32) -> Key {
        slru_block_to_key(
            SlruKind::MultiXactOffsets,
            pageno / pg_constants::SLRU_PAGES_PER_SEGMENT,
            pageno % pg_constants::SLRU_PAGES_PER_SEGMENT,
        )
    }

    fn zero_page() -> BytesMut {
        BytesMut::zeroed(BLCKSZ as usize)
    }

    fn entry(page: &[u8], mid: u32) -> u32 {
        let off = (mid % OFFSETS_PER_PAGE) as usize * 4;
        LittleEndian::read_u32(&page[off..off + 4])
    }

    fn set_entry(page: &mut [u8], mid: u32, moff: u32) {
        let off = (mid % OFFSETS_PER_PAGE) as usize * 4;
        LittleEndian::write_u32(&mut page[off..off + 4], moff);
    }

    fn apply(page: &mut BytesMut, pageno: u32, rec: NeonWalRecord) {
        apply_in_neon(&rec, Lsn(0x10), offsets_key(pageno), page).unwrap();
    }

    #[test]
    fn offset_create_writes_next_entry() {
        let mut page = zero_page();
        apply(
            &mut page,
            0,
            NeonWalRecord::MultixactOffsetCreateWithNext {
                mid: 5,
                moff: 10,
                next_moff: 13,
            },
        );

        let mut expected = zero_page();
        set_entry(&mut expected, 5, 10);
        set_entry(&mut expected, 6, 13);
        assert_eq!(page, expected);
    }

    #[test]
    fn next_entry_not_overwritten_when_set() {
        // Multixact 7 raced ahead and its own record already set entry 7.
        let mut page = zero_page();
        set_entry(&mut page, 7, 99);
        apply(
            &mut page,
            0,
            NeonWalRecord::MultixactOffsetCreateWithNext {
                mid: 6,
                moff: 10,
                next_moff: 13,
            },
        );

        assert_eq!(entry(&page, 6), 10);
        assert_eq!(entry(&page, 7), 99);
    }

    #[test]
    fn create_with_next_splits_across_pages() {
        // mid is the last entry of page 0; next is entry 0 of page 1.
        let mid = OFFSETS_PER_PAGE - 1;
        let rec = NeonWalRecord::MultixactOffsetCreateWithNext {
            mid,
            moff: 10,
            next_moff: 13,
        };

        let mut page0 = zero_page();
        apply(&mut page0, 0, rec.clone());
        let mut expected0 = zero_page();
        set_entry(&mut expected0, mid, 10);
        assert_eq!(page0, expected0);

        let mut page1 = zero_page();
        apply(&mut page1, 1, rec);
        let mut expected1 = zero_page();
        set_entry(&mut expected1, mid + 1, 13);
        assert_eq!(page1, expected1);
    }

    #[test]
    fn create_with_next_wraps_to_first_multixact_id() {
        // The multixact after u32::MAX is FirstMultiXactId (1), on page 0; entry 0 stays unused.
        let rec = NeonWalRecord::MultixactOffsetCreateWithNext {
            mid: u32::MAX,
            moff: 10,
            next_moff: 13,
        };

        let mut last = zero_page();
        apply(&mut last, u32::MAX / OFFSETS_PER_PAGE, rec.clone());
        let mut expected_last = zero_page();
        set_entry(&mut expected_last, u32::MAX, 10);
        assert_eq!(last, expected_last);

        let mut first = zero_page();
        apply(&mut first, 0, rec);
        let mut expected_first = zero_page();
        set_entry(&mut expected_first, pg_constants::FIRST_MULTIXACT_ID, 13);
        assert_eq!(first, expected_first);
    }

    #[test]
    #[should_panic(expected = "unexpected key")]
    fn create_with_next_on_unrelated_page_panics() {
        let mut page = zero_page();
        apply(
            &mut page,
            3,
            NeonWalRecord::MultixactOffsetCreateWithNext {
                mid: 5,
                moff: 10,
                next_moff: 13,
            },
        );
    }

    /// Review focus 3: pages built only from the old record (every layer stored
    /// before this change) reconstruct byte-for-byte as before.
    #[test]
    fn old_offset_records_reconstruct_unchanged() {
        let mut page = zero_page();
        for (mid, moff) in [(5, 10), (6, 13), (OFFSETS_PER_PAGE - 1, 40)] {
            apply(
                &mut page,
                0,
                NeonWalRecord::MultixactOffsetCreate { mid, moff },
            );
        }

        let mut expected = zero_page();
        expected[20..24].copy_from_slice(&10u32.to_le_bytes());
        expected[24..28].copy_from_slice(&13u32.to_le_bytes());
        let last = (OFFSETS_PER_PAGE as usize - 1) * 4;
        expected[last..last + 4].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(page, expected);
    }
}
