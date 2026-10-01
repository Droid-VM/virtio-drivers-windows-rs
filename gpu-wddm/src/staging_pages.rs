//! Fixed-size page leases for DMA command staging. The queue worker is the
//! sole owner; a slot's lease lasts until its descriptor is returned in used.

#[derive(Clone, Copy, Default)]
struct Lease {
    start: u16,
    pages: u16,
}

pub(crate) struct StagingPages<const PAGES: usize, const SLOTS: usize> {
    used: [bool; PAGES],
    leases: [Lease; SLOTS],
}

impl<const PAGES: usize, const SLOTS: usize> StagingPages<PAGES, SLOTS> {
    pub(crate) fn new() -> Self {
        assert!(PAGES <= u16::MAX as usize);
        Self { used: [false; PAGES], leases: [Lease::default(); SLOTS] }
    }

    /// Reserve contiguous pages, or leave the allocator unchanged when full.
    pub(crate) fn acquire(&mut self, slot: usize, pages: usize) -> Option<usize> {
        assert_eq!(self.leases[slot].pages, 0);
        if pages == 0 || pages > PAGES { return None; }
        let mut run = 0;
        for end in 0..PAGES {
            run = if self.used[end] { 0 } else { run + 1 };
            if run == pages {
                let start = end + 1 - pages;
                self.used[start..=end].fill(true);
                self.leases[slot] = Lease { start: start as u16, pages: pages as u16 };
                return Some(start);
            }
        }
        None
    }

    pub(crate) fn release(&mut self, slot: usize) {
        let lease = core::mem::take(&mut self.leases[slot]);
        let start = lease.start as usize;
        self.used[start..start + lease.pages as usize].fill(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_host_reads_survive_other_completions_and_reuse() {
        let mut pages = StagingPages::<8, 4>::new();
        let mut memory = [0u8; 8];
        let a = pages.acquire(0, 3).unwrap();
        memory[a..a + 3].fill(11);
        let b = pages.acquire(1, 3).unwrap();
        memory[b..b + 3].fill(22);
        assert_eq!(pages.acquire(2, 3), None);
        pages.release(1); // The host finishes B before A.
        let c = pages.acquire(2, 4).unwrap();
        memory[c..c + 4].fill(33);
        assert_eq!(&memory[a..a + 3], &[11; 3]); // Delayed host read of A.
        pages.release(0);
        pages.release(2);
        assert_eq!(pages.acquire(3, 8), Some(0));
    }

    #[test]
    fn fragmentation_waits_without_losing_ownership() {
        let mut pages = StagingPages::<8, 5>::new();
        for slot in 0..4 { assert_eq!(pages.acquire(slot, 2), Some(slot * 2)); }
        pages.release(0);
        pages.release(2);
        assert_eq!(pages.acquire(4, 4), None);
        pages.release(1);
        assert_eq!(pages.acquire(4, 4), Some(0));
        pages.release(3);
        pages.release(4);
        assert_eq!(pages.acquire(0, 8), Some(0));
    }

    #[test]
    fn invalid_sizes_and_unused_slots_do_not_consume_pages() {
        let mut pages = StagingPages::<8, 2>::new();
        assert_eq!(pages.acquire(0, 0), None);
        assert_eq!(pages.acquire(0, 9), None);
        pages.release(1);
        assert_eq!(pages.acquire(0, 8), Some(0));
        assert_eq!(pages.acquire(1, 1), None);
        pages.release(0);
        assert_eq!(pages.acquire(1, 8), Some(0));
    }
}
