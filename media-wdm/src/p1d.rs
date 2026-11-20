//! P2-1: the virtio-media session, driven by user-mode IOCTLs.
//!
//! P1d-2 proved the full decode sequence from `EvtDevicePrepareHardware`:
//! OPEN, S_FMT(H264), S_FMT(NV12), REQBUFS, QUERYBUF, MMAP, QBUF,
//! SUBSCRIBE_EVENT(SOURCE_CHANGE), STREAMON, DQBUF.  P2-1 keeps exactly those
//! protocol steps and splits them into three IOCTL-sized operations:
//!
//!   * [`open_session`]  - the OPEN command (one per session),
//!   * [`configure_and_send`] - everything P1d did before polling, with the
//!     H.264 access unit supplied by the caller instead of the embedded blob,
//!   * [`take_frame`]    - P1d's eventq poll and NV12 copy, into a caller buffer.
//!
//! The transport (BAR mapping, vrings, pool) is still brought up in
//! `EvtDevicePrepareHardware`; this file only speaks virtio-media/V4L2.
//!
//! The old P1d/P1d-2 behavior (send the embedded IDR, write
//! `C:\DroidVM\p1d\frame.raw`) is intentionally gone: the user-mode test owns
//! the bitstream and the output file now.

use super::*;

pub(crate) const EVENT_DMA_LEN: usize =
    virtio_media::EVENT_COUNT as usize * virtio_media::EVENT_CAP;

// ---- 1.0.0.23 CACHED-POOL: cache maintenance ------------------------------
//
// The `media_host` pool is ordinary guest RAM that **the host** writes (the
// decoded frame) and the guest CPU reads: `MAP_FRAME` hands the caller a user VA
// over those very pages, `GET_FRAME` copies them in the kernel, and the access
// unit we pass the other way is written into an OUTPUT buffer of the same pool.
// Up to 1.0.0.22 both mappings were `MmNonCached` (because "the host wrote it,
// so a cached read could be stale"), and one 1080p NV12 read -- 3,133,440 B --
// cost **30.35 ms = 103 MB/s**: every load went out to memory.
//
// 1.0.0.23 maps both `MmCached` and pays explicit maintenance per frame:
//
//   * host -> guest (capture buffer pixels): `dc ivac` ("invalidate by VA to
//     PoC") over the frame window, after `DQBUF` says the buffer is complete and
//     before the caller may read it.  `ivac` **discards** the line instead of
//     writing it back, which is exactly right: the guest never writes
//     capture-buffer pixels, so there is no dirty guest line to lose, and the
//     next load refills from memory where the host left the pixels.
//   * guest -> host (the access unit copied into the OUTPUT buffer):
//     `dc civac` ("clean and invalidate") after the copy and before `QBUF`, so
//     our dirty lines are written back and the host's view of memory is current.
//
// API choice -- why not the WDK routines one would reach for first:
//   * `KeFlushCurrentTbImmediately()` flushes the **TLB**, not the data cache:
//     it cannot make a stale cached read correct.
//   * `KeFlushIoBuffers(Mdl, ReadOperation, DmaOperation)` is the DMA-coherency
//     helper.  It takes an MDL (not a range), and its ARM64 implementation only
//     maintains cache for pages whose MDL the I/O manager built; our mappings
//     come from hand-built PFN MDLs (`MdlOwned::from_locked_pfns`).  Using it
//     would mean building a throw-away MDL per frame on top of the mapping we
//     already have, for the same DC instructions underneath.
//   * `RtlCopyMemoryNonTemporal` is a *store* hint (no-allocate destination).  It
//     does not invalidate a reader's lines, so it cannot make a stale read
//     correct -- it would only help a streaming write.
// `dsb sy` after the loop publishes the maintenance to the memory system (an
// `isb` follows so no later instruction runs on a stale context); the loop
// itself is one instruction per line, so a 3.1 MB window (48,960 lines) is a few
// tens of microseconds -- measured and logged per frame as `cache=<us>`.

/// AArch64 minimum data-cache line size, from `CTR_EL0.DminLine`.
#[inline]
pub(crate) fn data_cache_line_bytes() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let ctr: u64;
        unsafe {
            core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nostack, preserves_flags));
        }
        let dmin = ((ctr >> 16) & 0xF) as usize;
        let line = 4usize << dmin;
        if line == 0 { 64 } else { line }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        64
    }
}

/// `dc ivac` over `[va, va + len)`: drop any cached copy so the next load reads
/// memory.  For memory the **host** wrote and the guest only reads.
pub(crate) unsafe fn cache_invalidate_range(va: *const u8, len: usize) {
    if va.is_null() || len == 0 {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let line = data_cache_line_bytes();
        let start = (va as usize) & !(line - 1);
        let end = (va as usize).wrapping_add(len);
        let mut p = start;
        while p < end {
            core::arch::asm!("dc ivac, {}", in(reg) p, options(nostack, preserves_flags));
            p = p.wrapping_add(line);
        }
        core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (va, len);
    }
}

/// `dc civac` over `[va, va + len)`: write our dirty lines back **and** drop
/// them.  For memory the **guest** wrote that the host is about to read.
pub(crate) unsafe fn cache_clean_invalidate_range(va: *const u8, len: usize) {
    if va.is_null() || len == 0 {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        let line = data_cache_line_bytes();
        let start = (va as usize) & !(line - 1);
        let end = (va as usize).wrapping_add(len);
        let mut p = start;
        while p < end {
            core::arch::asm!("dc civac, {}", in(reg) p, options(nostack, preserves_flags));
            p = p.wrapping_add(line);
        }
        core::arch::asm!("dsb sy", "isb", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (va, len);
    }
}

/// True when the pool's kernel mapping (and the per-frame user mapping over the
/// same pages) is `MmCached`.  Set once by [`map_pool`]; `false` means the
/// platform refused the cached mapping and we fell back to `MmNonCached`, in
/// which case no maintenance is needed (or wanted: the DC instructions are only
/// architecturally defined for Normal cacheable memory).
pub(crate) static POOL_CACHED: AtomicBool = AtomicBool::new(false);

/// One contiguous, noncached bump for the eventq buffers.
pub(crate) struct EventDma {
    pub(crate) va: *mut u8,
    pub(crate) pa: u64,
    pub(crate) len: usize,
}

impl EventDma {
    pub(crate) unsafe fn alloc(log: &mut dyn virtio_media::Log) -> Option<Self> {
        let va = wdm::MmAllocateContiguousMemorySpecifyCache(
            EVENT_DMA_LEN as u64,
            wdm::PHYSICAL_ADDRESS { QuadPart: 0 },
            wdm::PHYSICAL_ADDRESS { QuadPart: -1 },
            wdm::PHYSICAL_ADDRESS { QuadPart: 0 },
            wdm::MEMORY_CACHING_TYPE::MmNonCached,
        );
        if va.is_null() {
            vlog(log, format_args!("MmAllocateContiguousMemorySpecifyCache({}) failed", EVENT_DMA_LEN));
            return None;
        }
        let pa = wdm::MmGetPhysicalAddress(va).QuadPart as u64;
        ptr::write_bytes(va as *mut u8, 0, EVENT_DMA_LEN);
        vlog(
            log,
            format_args!(
                "event dma: va=0x{:X} pa=0x{:X} len={} ({} x {} B)",
                va as usize,
                pa,
                EVENT_DMA_LEN,
                virtio_media::EVENT_COUNT,
                virtio_media::EVENT_CAP
            ),
        );
        Some(Self { va: va as *mut u8, pa, len: EVENT_DMA_LEN })
    }

    pub(crate) fn buf(&self, index: u16) -> virtio_media::Buf {
        let off = index as usize * virtio_media::EVENT_CAP;
        virtio_media::Buf {
            va: unsafe { self.va.add(off) },
            pa: self.pa + off as u64,
            len: virtio_media::EVENT_CAP,
        }
    }
}

impl Drop for EventDma {
    fn drop(&mut self) {
        unsafe { wdm::MmFreeContiguousMemory(self.va as *mut c_void) };
    }
}

pub(crate) const MAX_CAPTURE_BUFS: usize = 32;
pub(crate) const MAX_OUTPUT_BUFS: usize = 8;
pub(crate) const CAPTURE_BUFS: u32 = 32;
/// 1.0.0.20 / E173: never ask for fewer than this, even when the pool budget is
/// tiny.  A decode queue shorter than two buffers cannot pipeline one frame
/// while the client holds another, so failing is better than granting one.
pub(crate) const MIN_CAPTURE_BUFS: u32 = 2;
/// P3/1.0.0.10: two OUTPUT buffers are enough because SEND waits for the
/// device's DQBUF(OUTPUT) before it reuses a buffer (see [`submit_access_unit`])
/// and the two-session case must still fit the 64 MiB `media_host` pool:
/// 20 NV12 720p CAPTURE buffers (26.4 MiB) + 2 x 1 MiB OUTPUT.
pub(crate) const OUTPUT_BUFS: u32 = 2;
/// 500 us per wait: since 1.0.0.17 that is one `irq::wait()` (a 500 us block on
/// the device's ring-progress event) and only falls back to a busy stall when no
/// interrupt is delivered, so a command timeout of 20,000 spins is still 10 s.
pub(crate) const COMMAND_SPINS: u32 = 20_000;

/// Everything S_FMT/REQBUFS/MMAP produced. Kept next to the live queues so
/// GET_FRAME can find the pool address of the capture buffer the device
/// returned.
#[derive(Clone, Copy)]
pub(crate) struct SessionConfig {
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) capture_stride: u32,
    pub(crate) capture_sizeimage: u32,
    /// HEVC-MAIN10: the fourcc the CAPTURE queue ended up with -- 'NV12' always
    /// before 1.0.0.21, 'P010' when a Main10 session's S_FMT CAPTURE was
    /// accepted.  `capture_bit_depth` is 8 or 10 accordingly, and both are
    /// reported to the client in `VM_FRAME_INFO.FourCC` / row arithmetic.
    pub(crate) capture_fourcc: u32,
    pub(crate) capture_bit_depth: u32,
    pub(crate) output_sizeimage: u32,
    pub(crate) capture_count: u32,
    pub(crate) cap_va: [*mut u8; MAX_CAPTURE_BUFS],
    pub(crate) cap_len: [u32; MAX_CAPTURE_BUFS],
    pub(crate) cap_off: [u32; MAX_CAPTURE_BUFS],
    /// `driver_addr` the device returned for each MMAP.  P2-2f needs it to give
    /// the pool range back with `VIRTIO_MEDIA_CMD_MUNMAP`; without it every
    /// decoded session permanently eats 20 * sizeimage of the media_host pool
    /// and REQBUFS starts failing with ENOMEM after two sessions.
    pub(crate) cap_addr: [u64; MAX_CAPTURE_BUFS],
    /// P3-6 / 1.0.0.12: bit i set while capture buffer i's pool range is still
    /// mapped (i.e. we owe a MUNMAP for it).  This is what the release sweep
    /// walks, **not** `cap_addr[i] != 0`: the device hands the first mapping of a
    /// session pool offset 0, so an `addr == 0` test silently skipped it and
    /// pinned one full frame of the pool (3.13 MiB at 1080p) for the life of the
    /// device -- the pool then answered REQBUFS with ENOMEM on the next 1080p
    /// session (E148).
    pub(crate) cap_mapped: u32,
    pub(crate) output_count: u32,
    pub(crate) out_va: [*mut u8; MAX_OUTPUT_BUFS],
    pub(crate) out_len: [u32; MAX_OUTPUT_BUFS],
    pub(crate) out_off: [u32; MAX_OUTPUT_BUFS],
    pub(crate) out_addr: [u64; MAX_OUTPUT_BUFS],
    /// Bit i set while output buffer i's pool range is still mapped.
    pub(crate) out_mapped: u32,
    /// P3/1.0.0.10: the session is configured (S_FMT/REQBUFS/MMAP/STREAMON done).
    /// The first SEND configures and sends; every later SEND only queues another
    /// access unit on the same host session -- the P2-1 "one AU per session"
    /// restriction is gone.
    pub(crate) configured: bool,
    pub(crate) send_tag: u64,
    pub(crate) cap_tag: [u64; MAX_CAPTURE_BUFS],
    /// Bit i set: CAPTURE buffer i is queued (lent) on the device.  Cleared on
    /// DQBUF(CAPTURE), set again after the frame is copied and re-queued.
    pub(crate) cap_queued: u32,
    /// Bit i set: OUTPUT buffer i is free (not lent) and can take an access unit.
    pub(crate) out_free: u32,
    /// Access units queued on this session (1 = the one configure_and_send did).
    pub(crate) aus_queued: u64,
    pub(crate) stop_failed: bool,
    /// How many DQBUF lines of each queue were logged (the per-frame lines are
    /// the evidence; logging every DQBUF would fill the 64 KiB ring too fast).
    pub(crate) dqb_cap_logged: u8,
    pub(crate) dqb_out_logged: u8,
}

impl SessionConfig {
    /// SAFETY: `dst` points to exclusive, aligned, uninitialized final storage.
    unsafe fn init_empty_at(dst: *mut Self) {
        macro_rules! field { ($name:ident, $value:expr) => {
            ptr::addr_of_mut!((*dst).$name).write($value);
        }; }
        macro_rules! array { ($name:ident, $ty:ty, $n:expr, $value:expr) => {
            let base = ptr::addr_of_mut!((*dst).$name).cast::<$ty>();
            for i in 0..$n { base.add(i).write($value); }
        }; }
        field!(width, 0);
        field!(height, 0);
        field!(capture_stride, 0);
        field!(capture_sizeimage, 0);
        field!(capture_fourcc, virtio_media::V4L2_PIX_FMT_NV12);
        field!(capture_bit_depth, 8);
        field!(output_sizeimage, 0);
        field!(capture_count, 0);
        array!(cap_va, *mut u8, MAX_CAPTURE_BUFS, ptr::null_mut());
        array!(cap_len, u32, MAX_CAPTURE_BUFS, 0);
        array!(cap_off, u32, MAX_CAPTURE_BUFS, 0);
        array!(cap_addr, u64, MAX_CAPTURE_BUFS, 0);
        field!(cap_mapped, 0);
        field!(output_count, 0);
        array!(out_va, *mut u8, MAX_OUTPUT_BUFS, ptr::null_mut());
        array!(out_len, u32, MAX_OUTPUT_BUFS, 0);
        array!(out_off, u32, MAX_OUTPUT_BUFS, 0);
        array!(out_addr, u64, MAX_OUTPUT_BUFS, 0);
        field!(out_mapped, 0);
        field!(configured, false);
        field!(send_tag, 0);
        array!(cap_tag, u64, MAX_CAPTURE_BUFS, 0);
        field!(cap_queued, 0);
        field!(out_free, 0);
        field!(aus_queued, 0);
        field!(stop_failed, false);
        field!(dqb_cap_logged, 0);
        field!(dqb_out_logged, 0);
    }

    pub(crate) const fn empty() -> Self {
        Self {
            width: 0,
            height: 0,
            capture_stride: 0,
            capture_sizeimage: 0,
            capture_fourcc: virtio_media::V4L2_PIX_FMT_NV12,
            capture_bit_depth: 8,
            output_sizeimage: 0,
            capture_count: 0,
            cap_va: [ptr::null_mut(); MAX_CAPTURE_BUFS],
            cap_len: [0; MAX_CAPTURE_BUFS],
            cap_off: [0; MAX_CAPTURE_BUFS],
            cap_addr: [0; MAX_CAPTURE_BUFS],
            cap_mapped: 0,
            output_count: 0,
            out_va: [ptr::null_mut(); MAX_OUTPUT_BUFS],
            out_len: [0; MAX_OUTPUT_BUFS],
            out_off: [0; MAX_OUTPUT_BUFS],
            out_addr: [0; MAX_OUTPUT_BUFS],
            out_mapped: 0,
            configured: false,
            send_tag: 0,
            cap_tag: [0; MAX_CAPTURE_BUFS],
            cap_queued: 0,
            out_free: 0,
            aus_queued: 0,
            stop_failed: false,
            dqb_cap_logged: 0,
            dqb_out_logged: 0,
        }
    }
}

/// Dequeue results that arrived while SEND was waiting for an OUTPUT buffer, so
/// GET_FRAME still returns every frame exactly once.  (With the UMD's
/// SEND-then-GET_FRAME lockstep this stays empty; it is the safety net for the
/// case where a DQBUF(OUTPUT) and a DQBUF(CAPTURE) arrive in the same event
/// batch and SEND has to drain that batch to find a free OUTPUT buffer.)
pub(crate) const MAX_PENDING_FRAMES: usize = MAX_CAPTURE_BUFS;

#[derive(Clone, Copy)]
pub(crate) struct PendingFrames {
    pub(crate) index: [u32; MAX_PENDING_FRAMES],
    pub(crate) used: [u32; MAX_PENDING_FRAMES],
    pub(crate) head: u8,
    pub(crate) len: u8,
}

impl PendingFrames {
    pub(crate) const fn empty() -> Self {
        Self { index: [0; MAX_PENDING_FRAMES], used: [0; MAX_PENDING_FRAMES], head: 0, len: 0 }
    }

    pub(crate) fn push(&mut self, index: u32, used: u32) {
        if self.len as usize >= MAX_PENDING_FRAMES {
            return;
        }
        let at = (self.head as usize + self.len as usize) % MAX_PENDING_FRAMES;
        self.index[at] = index;
        self.used[at] = used;
        self.len += 1;
    }

    pub(crate) fn pop(&mut self) -> Option<(u32, u32)> {
        if self.len == 0 {
            return None;
        }
        let at = self.head as usize;
        let out = (self.index[at], self.used[at]);
        self.head = ((self.head as usize + 1) % MAX_PENDING_FRAMES) as u8;
        self.len -= 1;
        Some(out)
    }
}

/// One capture buffer mapped into the calling process (P-BATCH ZEROCOPY).
///
/// The pages are the `media_host` pool's own pages: the MDL only *describes*
/// the PFNs the driver derived from the ACPI range, it does not own them, so
/// dropping it frees the descriptor and never the memory.  The user VA must go
/// away with `mm_unmap_locked_pages` from the process that created it; the MDL
/// is then freed by `MdlOwned`'s `Drop`.
pub(crate) struct MappedFrame {
    pub(crate) mdl: wdk::wdm::MdlOwned,
    /// page-aligned start of the mapping in the caller's address space
    pub(crate) va: core::ptr::NonNull<u8>,
    /// bytes mapped at `va` (page-rounded window around the picture)
    pub(crate) len: u32,
    /// capture buffer index this window belongs to (what RELEASE requeues)
    pub(crate) index: u32,
    /// bytes from `va` to the first decoded byte
    pub(crate) delta: u32,
}

/// CONCURRENT-MAPPING (1.0.0.22): one slot of the per-capture-buffer mapping
/// table.  `process` is `IoGetCurrentProcess` at MAP_FRAME time: a user VA only
/// means something inside the address space that created it, so RELEASE and
/// every teardown path have to check it before `mm_unmap_locked_pages`.
pub(crate) struct MappingEntry {
    pub(crate) frame: MappedFrame,
    pub(crate) process: usize,
    /// Exactly what MAP_FRAME answered, kept so a duplicate MAP_FRAME for the
    /// same index can answer the same VA instead of failing (idempotent).
    pub(crate) out: vmedia_abi::VM_FRAME_MAP,
}

/// What a whole-table release took down: the capture buffer indices that have to
/// be requeued, how many windows were unmapped in this process and how many
/// belonged to another address space (that VA dies with its own process).
pub(crate) struct ReleasedMappings {
    pub(crate) indices: [u32; MAX_CAPTURE_BUFS],
    pub(crate) count: usize,
    pub(crate) unmapped: u32,
    pub(crate) foreign: u32,
}

/// CONCURRENT-MAPPING (1.0.0.22): **one mapping per capture buffer index**.
///
/// 1.0.0.18..1.0.0.21 kept a single `Option<MappedFrame>` per session and
/// refused a second MAP_FRAME with `ST_INVALID_DEVICE_STATE` ("the previous
/// frame was never released", user mode err=22).  That made a capture pool of
/// 18..20 buffers behave like a single buffer: a client that keeps more than one
/// frame in flight -- or simply maps the next frame before it has finished
/// reading the previous one -- failed on its second frame, on every codec.
///
/// The pool is what limits concurrency, so the driver models it as a table: as
/// many entries as `capture_count` can be out at once, each released by its own
/// index.  The table lives next to `SessionConfig` and is torn down before the
/// pool's kernel mapping (these windows describe the pool's PFNs).
pub(crate) struct MappingTable {
    slots: [Option<MappingEntry>; MAX_CAPTURE_BUFS],
    live: u32,
    /// high-water mark of simultaneously live mappings (log evidence)
    high_water: u32,
    /// MAP_FRAME replayed an index that was already mapped (idempotent answer)
    duplicates: u32,
    /// MAP_FRAME refused because every capture buffer was already mapped
    exhausted: u32,
    /// RELEASE_FRAME for an index that is not mapped (stale/duplicate release)
    unknown_releases: u32,
}

impl MappingTable {
    /// Initialize directly in the final allocation; never materialize the 32-entry table.
    /// SAFETY: `dst` is aligned, writable, uninitialized storage, exclusively owned.
    unsafe fn init_empty_at(dst: *mut Self) {
        let slots = ptr::addr_of_mut!((*dst).slots).cast::<Option<MappingEntry>>();
        for i in 0..MAX_CAPTURE_BUFS {
            slots.add(i).write(None);
        }
        ptr::addr_of_mut!((*dst).live).write(0);
        ptr::addr_of_mut!((*dst).high_water).write(0);
        ptr::addr_of_mut!((*dst).duplicates).write(0);
        ptr::addr_of_mut!((*dst).exhausted).write(0);
        ptr::addr_of_mut!((*dst).unknown_releases).write(0);
    }

    pub(crate) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            live: 0,
            high_water: 0,
            duplicates: 0,
            exhausted: 0,
            unknown_releases: 0,
        }
    }

    pub(crate) fn len(&self) -> u32 {
        self.live
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub(crate) fn high_water(&self) -> u32 {
        self.high_water
    }

    pub(crate) fn duplicates(&self) -> u32 {
        self.duplicates
    }

    pub(crate) fn exhausted(&self) -> u32 {
        self.exhausted
    }

    pub(crate) fn unknown_releases(&self) -> u32 {
        self.unknown_releases
    }

    pub(crate) fn contains(&self, index: u32) -> bool {
        (index as usize) < MAX_CAPTURE_BUFS && self.slots[index as usize].is_some()
    }

    /// The mapping of `index`, if it is out.  `None` covers both "never mapped"
    /// and "out of range", which are the same answer for a release.
    pub(crate) fn get(&self, index: u32) -> Option<&MappingEntry> {
        if (index as usize) >= MAX_CAPTURE_BUFS {
            return None;
        }
        self.slots[index as usize].as_ref()
    }

    /// Publish the mapping the caller just built.  `Err((true, entry))` = that
    /// index is already mapped (the entry is handed back untouched and the
    /// caller must not lose it), `Err((false, entry))` = index out of range.
    pub(crate) fn insert(&mut self, entry: MappingEntry) -> Result<(), (bool, MappingEntry)> {
        let index = entry.frame.index as usize;
        if index >= MAX_CAPTURE_BUFS {
            return Err((false, entry));
        }
        if self.slots[index].is_some() {
            self.duplicates = self.duplicates.saturating_add(1);
            return Err((true, entry));
        }
        self.slots[index] = Some(entry);
        self.live = self.live.saturating_add(1);
        if self.live > self.high_water {
            self.high_water = self.live;
        }
        Ok(())
    }

    /// Take one mapping out without touching its user VA: the caller either
    /// unmaps it (own process) or drops it, and always requeues the index.
    pub(crate) fn take(&mut self, index: u32) -> Option<MappingEntry> {
        if (index as usize) >= MAX_CAPTURE_BUFS {
            return None;
        }
        let taken = self.slots[index as usize].take();
        if taken.is_some() {
            self.live = self.live.saturating_sub(1);
        }
        taken
    }

    pub(crate) fn note_exhausted(&mut self) {
        self.exhausted = self.exhausted.saturating_add(1);
    }

    pub(crate) fn note_unknown_release(&mut self) {
        self.unknown_releases = self.unknown_releases.saturating_add(1);
    }

    /// Tear the whole table down.  A window owned by `here` is unmapped
    /// properly; a window owned by another process only loses its MDL (the VA
    /// belongs to that address space and dies with it).  Must run at
    /// PASSIVE_LEVEL and **before** the pool's kernel mapping is released.
    pub(crate) unsafe fn release_all(&mut self, here: usize) -> ReleasedMappings {
        let mut out = ReleasedMappings {
            indices: [0; MAX_CAPTURE_BUFS],
            count: 0,
            unmapped: 0,
            foreign: 0,
        };
        for slot in self.slots.iter_mut() {
            let Some(entry) = slot.take() else { continue };
            self.live = self.live.saturating_sub(1);
            if out.count < out.indices.len() {
                out.indices[out.count] = entry.frame.index;
                out.count += 1;
            }
            if entry.process == here {
                unmap_frame(entry.frame);
                out.unmapped = out.unmapped.saturating_add(1);
            } else {
                // A VA of another address space is not ours to unmap; dropping
                // the MDL is all that is left (and all that is needed: the pool
                // pages are not allocated by the MDL).
                drop(entry.frame);
                out.foreign = out.foreign.saturating_add(1);
            }
        }
        out
    }
}

/// SESSION-OWNERSHIP (1.0.0.24): the **device transport** -- one per virtio-media
/// function, shared by every session of that function.  Nothing here is
/// per-session: the two virtqueues, the DMA block, the BAR mapping, the event
/// buffers and the kernel mapping of the `media_host` pool are created once in
/// `EvtDevicePrepareHardware` and torn down in `EvtDeviceReleaseHardware`.
pub(crate) struct Io {
    pub(crate) dma: Dma,
    pub(crate) q0: virtio_media::Queue,
    pub(crate) mmio: Kmmio,
    pub(crate) pool_va: *mut u8,
    pub(crate) pool_len: usize,
    /// P-BATCH ZEROCOPY: guest-physical base of the pool, so the capture-buffer
    /// pages can be described as PFNs for a user-mode mapping.  (`pool_va` is
    /// the kernel's cached mapping of the same range.)
    pub(crate) pool_pa: u64,
}

impl Io {
    pub(crate) fn req_base(&self) -> virtio_media::Buf {
        virtio_media::Buf {
            va: unsafe { self.dma.va.add(REQ_OFF) },
            pa: self.dma.pa + REQ_OFF as u64,
            len: REQ_CAP,
        }
    }

    pub(crate) fn resp_base(&self) -> virtio_media::Buf {
        virtio_media::Buf {
            va: unsafe { self.dma.va.add(RESP_OFF) },
            pa: self.dma.pa + RESP_OFF as u64,
            len: RESP_CAP,
        }
    }
}

/// SESSION-OWNERSHIP (1.0.0.24): **one decoder session** and everything that
/// belongs to it.  Before this, all of these fields lived directly on
/// `LiveState`, i.e. one session per device function, and every operation wrote
/// "the" session -- which is why a replaced decoder's CLOSE could destroy the
/// session that replaced it (media-wdm 1.0.0.23 `ioctl_close` cleared
/// `session_open`/`session_id`/`cfg`/`mappings` unconditionally).
///
/// `token` is the **generation** the client is told at OPEN and must send back
/// with every IOCTL.  It is never 0 and never reused, so "the session this
/// request belongs to" has an exact answer even after the host recycles its own
/// session id.  `host_id` is the virtio-media session id (what
/// `VM_OPEN_OUT.SessionId` reports) and only names the host object.
pub(crate) struct SessionSlot {
    pub(crate) open: bool,
    /// generation token handed to the client at OPEN / FLUSH (0 = never issued)
    pub(crate) token: u32,
    /// virtio-media (host) session id this slot currently owns
    pub(crate) host_id: u32,
    /// `VM_OPEN_IN.Codec` of the session (0 = H.264)
    pub(crate) codec: u32,
    pub(crate) cfg: SessionConfig,
    /// decoded frames met by SEND while it waited for a free OUTPUT buffer
    pub(crate) frames: PendingFrames,
    /// CONCURRENT-MAPPING: the capture buffers this session lent to user mode,
    /// keyed by index.  **Per session** since 1.0.0.24: two sessions can map the
    /// same index at the same time, and neither release may touch the other's.
    pub(crate) mappings: MappingTable,
    /// P3/1.0.0.10: access units queued but not yet answered by a GET_FRAME.
    pub(crate) pending_aus: u32,
    /// Session totals for the CLOSE summary line.
    pub(crate) aus_sent: u64,
    pub(crate) frames_got: u64,
    /// Requests that carried no token (a pre-1.0.0.24 client) and were served
    /// under the legacy rule "accepted only while it is the only session".
    pub(crate) legacy_requests: u32,
    /// Requests refused because their token named another (replaced) session.
    pub(crate) rejects: u32,
    /// PER-SESSION-LIVESTATE (1.0.0.25): `VIRTIO_MEDIA_EVENT_ERROR` errno that was
    /// **routed here by the other session's IOCTL** (the event queue is one
    /// hardware queue, so whatever request is running pumps it).  The owner sees
    /// it on its next SEND / GET_FRAME / MAP_FRAME -- exactly where it would have
    /// seen it had it pumped the event itself -- instead of the error failing
    /// whichever session happened to be running.
    pub(crate) event_err: i32,
    /// Completions of this session that the other session's pump delivered here
    /// (evidence for the dual-session run).
    pub(crate) routed: u32,
}

impl SessionSlot {
    /// Infallible: no allocation, callback or owned resource is acquired here.
    /// SAFETY: `dst` points to exclusive, aligned, uninitialized final storage.
    unsafe fn init_empty_at(dst: *mut Self) {
        macro_rules! field { ($name:ident, $value:expr) => {
            ptr::addr_of_mut!((*dst).$name).write($value);
        }; }
        field!(open, false);
        field!(token, 0);
        field!(host_id, 0);
        field!(codec, vmedia_abi::VM_OPEN_CODEC_H264);
        SessionConfig::init_empty_at(ptr::addr_of_mut!((*dst).cfg));
        let frames = ptr::addr_of_mut!((*dst).frames);
        let indices = ptr::addr_of_mut!((*frames).index).cast::<u32>();
        let used = ptr::addr_of_mut!((*frames).used).cast::<u32>();
        for i in 0..MAX_PENDING_FRAMES {
            indices.add(i).write(0);
            used.add(i).write(0);
        }
        ptr::addr_of_mut!((*frames).head).write(0);
        ptr::addr_of_mut!((*frames).len).write(0);
        MappingTable::init_empty_at(ptr::addr_of_mut!((*dst).mappings));
        field!(pending_aus, 0);
        field!(aus_sent, 0);
        field!(frames_got, 0);
        field!(legacy_requests, 0);
        field!(rejects, 0);
        field!(event_err, 0);
        field!(routed, 0);
    }

    pub(crate) fn empty() -> Self {
        Self {
            open: false,
            token: 0,
            host_id: 0,
            codec: vmedia_abi::VM_OPEN_CODEC_H264,
            cfg: SessionConfig::empty(),
            frames: PendingFrames::empty(),
            mappings: MappingTable::new(),
            pending_aus: 0,
            aus_sent: 0,
            frames_got: 0,
            legacy_requests: 0,
            rejects: 0,
            event_err: 0,
            routed: 0,
        }
    }

    /// Forget every trace of the session in the guest.  The host side (CLOSE,
    /// MUNMAP) is the caller's job; this only drops the bookkeeping the next
    /// OPEN must not inherit.
    pub(crate) fn clear(&mut self) {
        self.open = false;
        self.host_id = 0;
        self.pending_aus = 0;
        self.frames = PendingFrames::empty();
        self.cfg = SessionConfig::empty();
        self.aus_sent = 0;
        self.frames_got = 0;
        // PER-SESSION-LIVESTATE (1.0.0.25): a latched event error belongs to the
        // session that is going away, never to the next one that reuses the slot.
        self.event_err = 0;
        self.routed = 0;
    }
}

/// The answer to "does this request own the session it is talking about?".
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Owner {
    /// The live slot index.
    Live(usize),
    /// The token/hint named a session that is no longer live: the caller is a
    /// replaced (or pre-restart) client.  CLOSE ignores it, everything else
    /// refuses it.
    Stale,
    /// No token and no hint, while more than one session is open: a legacy
    /// client cannot be attributed, so it is refused instead of guessed.
    Ambiguous,
    /// No token and no hint, exactly one session open: legacy, and safe.
    Legacy(usize),
    /// No session is open at all.
    NoSession,
}

/// `VMEDIA_MAX_SESSIONS` as a `usize` for array types.
pub(crate) const VMEDIA_MAX_SESSIONS: usize = vmedia_abi::VMEDIA_MAX_SESSIONS as usize;

/// PER-SESSION-LIVESTATE (1.0.0.25): the **other** session of this function, as
/// seen from the one whose IOCTL is running right now.
///
/// The event queue is one hardware queue: whatever request is running pumps it,
/// and the host tags every event with the virtio-media session id it belongs to
/// (`event.session`).  Up to 1.0.0.24 an event for the other session was read,
/// logged as `event for session N (ours M) ignored` and **dropped** -- so the
/// other session's `DQBUF(OUTPUT)` never came back, its two OUTPUT buffers
/// stayed lent for ever, and its next SEND ended in
/// `SEND: no free OUTPUT buffer after 4000 spins` => `BeginFrame 0x80004005`.
/// That is exactly the Edge + PotPlayer dual-session failure (doc 37).
///
/// With this struct the completion is applied to the session that owns it (its
/// `cfg` masks, its `frames` queue, its `event_err` latch), and that session
/// finds it on its next IOCTL.  No lock is needed: the WDF IOCTL queue is
/// `WdfIoQueueDispatchSequential`, so two handlers never run at the same time
/// and "the other slot" is only ever touched from inside this request.
pub(crate) struct Fanout<'a> {
    /// Host/virtio-media session id of the session this IOCTL belongs to.
    pub(crate) own_host: u32,
    /// Slot index of the caller (`VMEDIA_MAX_SESSIONS`-bounded, the async owner).
    pub(crate) owner: u8,
    /// The other slot of the same function, `None` while it is closed.
    pub(crate) peer: Option<&'a mut SessionSlot>,
}

impl<'a> Fanout<'a> {
    pub(crate) fn new(own_host: u32, owner: usize, peer: Option<&'a mut SessionSlot>) -> Self {
        Self { own_host, owner: owner as u8, peer }
    }
}

/// Take the latched `VIRTIO_MEDIA_EVENT_ERROR` of `slot` (0 = none).  Called at
/// the entry of the handlers that would have pumped such an event themselves.
pub(crate) fn take_event_err(slot: &mut SessionSlot) -> i32 {
    let errno = slot.event_err;
    slot.event_err = 0;
    errno
}


/// The live transport + the sessions that ride on it. Dropping it closes every
/// session (best effort), resets the device and unmaps the pool.
pub(crate) struct LiveState {
    pub(crate) io: Io,
    /// SESSION-OWNERSHIP: `VMEDIA_MAX_SESSIONS` slots.
    pub(crate) sessions: [SessionSlot; VMEDIA_MAX_SESSIONS],
    /// The encoder function owns exactly one independent H.264 session; it does
    /// not occupy or mutate decoder SessionSlot queue/mapping state.
    pub(crate) encoder: crate::encoder_state::EncoderOwner,
    pub(crate) encoder_slot: crate::encoder_state::EncoderSlot,
    /// Next generation token.  Starts at 1 (0 means "no identity") and only
    /// grows, so a token is unique for the life of the device instance.
    pub(crate) next_token: u32,
    pub(crate) is_decoder: bool,
    pub(crate) device_caps: u32,
    pub(crate) device_type: u32,
    pub(crate) card: [u8; 32],
    /// P2-2f session-lifecycle counters, logged on every OPEN/CLOSE so a leaked
    /// session is visible in `VirtioMediaIoctlLog` without a kernel debugger.
    pub(crate) opens: u32,
    pub(crate) closes: u32,
    /// Sessions that were still open when a new OPEN found every slot busy and
    /// had to close the oldest one first.
    pub(crate) stale_closes: u32,
    /// CLOSE commands the device refused; the guest clears its state anyway.
    pub(crate) failed_closes: u32,
    /// Every IOCTL that reached this device instance (activity of the session).
    pub(crate) ioctls: u32,
    /// SESSION-OWNERSHIP evidence: requests with no token (legacy) and requests
    /// refused because their token named another session.
    pub(crate) legacy_requests: u32,
    pub(crate) ownership_rejects: u32,
}

impl LiveState {
    /// Allocate only uninitialized bytes. Failure leaves all transport holders
    /// untouched, so Probe's existing reset/unmap/drop error path owns cleanup.
    pub(crate) fn try_allocate() -> Option<Box<core::mem::MaybeUninit<Self>>> {
        let layout = alloc::alloc::Layout::new::<Self>();
        let raw = unsafe { alloc::alloc::alloc(layout) };
        if raw.is_null() { return None; }
        Some(unsafe { Box::from_raw(raw.cast::<core::mem::MaybeUninit<Self>>()) })
    }

    /// Initialize sessions/scalars before transport ownership is transferred.
    /// No fallible operations, whole SessionSlot, MappingTable or LiveState values.
    /// SAFETY: dst is exclusively owned, aligned, uninitialized storage. Caller
    /// must initialize `io` completely before assume_init/publishing the Box.
    pub(crate) unsafe fn init_metadata_at(
        dst: *mut Self, is_decoder: bool, device_caps: u32, device_type: u32,
        card: [u8; 32],
    ) {
        let sessions = ptr::addr_of_mut!((*dst).sessions).cast::<SessionSlot>();
        for i in 0..VMEDIA_MAX_SESSIONS {
            SessionSlot::init_empty_at(sessions.add(i));
        }
        ptr::addr_of_mut!((*dst).encoder).write(crate::encoder_state::EncoderOwner::empty());
        ptr::addr_of_mut!((*dst).encoder_slot).write(crate::encoder_state::EncoderSlot::new(4));
        macro_rules! field { ($name:ident, $value:expr) => {
            ptr::addr_of_mut!((*dst).$name).write($value);
        }; }
        field!(next_token, 1);
        field!(is_decoder, is_decoder);
        field!(device_caps, device_caps);
        field!(device_type, device_type);
        field!(card, card);
        field!(opens, 0);
        field!(closes, 0);
        field!(stale_closes, 0);
        field!(failed_closes, 0);
        field!(ioctls, 0);
        field!(legacy_requests, 0);
        field!(ownership_rejects, 0);
    }

    /// How many sessions are open right now (>= 1 while a session exists).
    pub(crate) fn open_sessions(&self) -> u32 {
        let mut n = 0;
        for s in self.sessions.iter() {
            if s.open {
                n += 1;
            }
        }
        n
    }

    /// The live slot that owns `token`, if any.
    pub(crate) fn find_token(&self, token: u32) -> Option<usize> {
        if token == vmedia_abi::VMEDIA_NO_SESSION_TOKEN {
            return None;
        }
        self.sessions.iter().position(|s| s.open && s.token == token)
    }

    /// The live slot whose *host* session id is `host_id`.  Only used for a
    /// legacy client that echoes `VM_OPEN_OUT.SessionId` but has no token: host
    /// ids are unique among live sessions, so this is still an exact match.
    pub(crate) fn find_host(&self, host_id: u32) -> Option<usize> {
        self.sessions.iter().position(|s| s.open && s.host_id == host_id)
    }

    /// The ownership decision for one request.  See [`Owner`].
    pub(crate) fn resolve(&self, token: u32, host_hint: u32) -> Owner {
        if token != vmedia_abi::VMEDIA_NO_SESSION_TOKEN {
            return match self.find_token(token) {
                Some(i) => Owner::Live(i),
                None => Owner::Stale,
            };
        }
        if host_hint != 0 {
            if let Some(i) = self.find_host(host_hint) {
                return Owner::Legacy(i);
            }
            // A host id that no live session has: the session it named is gone.
            // Do not fall through to "the only open one" -- that is exactly the
            // misattribution this change removes.
            return Owner::Stale;
        }
        match self.open_sessions() {
            0 => Owner::NoSession,
            1 => Owner::Legacy(self.sessions.iter().position(|s| s.open).unwrap_or(0)),
            _ => Owner::Ambiguous,
        }
    }

    /// Allocate the next generation token.  Never 0, never reused.
    pub(crate) fn alloc_token(&mut self) -> u32 {
        if self.next_token == 0 {
            self.next_token = 1;
        }
        let t = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        if self.next_token == 0 {
            // 2^32 OPENs on one device instance: only reachable after a wrap.
            // Skip 0 (it means "legacy") and keep going.
            self.next_token = 1;
        }
        t
    }

    /// The oldest live session (lowest token), used when every slot is busy.
    pub(crate) fn oldest(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, s) in self.sessions.iter().enumerate() {
            if !s.open {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) if s.token < self.sessions[b].token => best = Some(i),
                _ => {}
            }
        }
        best
    }

    /// A free slot, if any.
    pub(crate) fn free_slot(&self) -> Option<usize> {
        self.sessions.iter().position(|s| !s.open)
    }

    /// Split the state into the device transport and one session.
    ///
    /// The two references point at disjoint fields, so the compiler accepts the
    /// borrow and every handler below can hold both at once (`configure_and_send`
    /// needs the queues *and* the session's `cfg`).
    pub(crate) fn split(&mut self, i: usize) -> (&mut Io, &mut SessionSlot) {
        (&mut self.io, &mut self.sessions[i])
    }

    /// PER-SESSION-LIVESTATE (1.0.0.25): split into the transport, the session the
    /// request belongs to, and **the other** session of the same function (if it
    /// is open), so the running handler can deliver a completion the host
    /// addressed to that other session instead of dropping it (see [`Fanout`]).
    pub(crate) fn split2(
        &mut self,
        i: usize,
    ) -> (&mut Io, &mut SessionSlot, Option<&mut SessionSlot>) {
        debug_assert!(i < VMEDIA_MAX_SESSIONS);
        let (head, tail) = self.sessions.split_at_mut(i);
        let (own, after) = tail.split_at_mut(1);
        let peer = head.iter_mut().chain(after.iter_mut()).find(|s| s.open);
        (&mut self.io, &mut own[0], peer)
    }
}

impl Drop for LiveState {
    fn drop(&mut self) {
        unsafe {
            // SESSION-OWNERSHIP: every session is closed by its **own** host id,
            // and its mappings go away **before** the pool's kernel mapping is
            // torn down (a window describes the pool's own PFNs).  A window left
            // behind would keep a user VA pointed at pages this instance is
            // about to unmap.
            let here = wdm::IoGetCurrentProcess() as usize;
            for i in 0..VMEDIA_MAX_SESSIONS {
                let open = self.sessions[i].open;
                let host_id = self.sessions[i].host_id;
                let token = self.sessions[i].token;
                {
                    let live = self.sessions[i].mappings.len();
                    let high = self.sessions[i].mappings.high_water();
                    let released = self.sessions[i].mappings.release_all(here);
                    if released.count != 0 || live != 0 {
                        virtio_media::log_args(
                            &mut IoLog,
                            format_args!(
                                "SESSION-OWNERSHIP: teardown of token {} released {} of {} live mapping(s) ({} unmapped here, {} foreign process, high-water {})",
                                token, released.count, live, released.unmapped, released.foreign, high
                            ),
                        );
                    }
                }
                if open {
                    let req = self.io.req_base();
                    let resp = self.io.resp_base();
                    let mut log = IoLog;
                    // Short timeout: this runs from EvtDeviceReleaseHardware.
                    let _ = close_session(
                        &mut self.io.mmio,
                        &mut self.io.q0,
                        &req,
                        &resp,
                        host_id,
                        &mut self.sessions[i].cfg,
                        200,
                        &mut log,
                    );
                    self.sessions[i].open = false;
                }
                // 1.0.0.12: a session that was already closed can still owe pool
                // ranges (a refused CLOSE, a client that died mid-configure).
                // Give them back before the transport goes away, so the next
                // instance does not start against a pool this one filled.
                if pending_mappings(&self.sessions[i].cfg) != 0 {
                    let req = self.io.req_base();
                    let resp = self.io.resp_base();
                    let mut log = IoLog;
                    let _ = release_all_mappings(
                        &mut self.io.mmio,
                        &mut self.io.q0,
                        &req,
                        &resp,
                        &mut self.sessions[i].cfg,
                        &mut log,
                    );
                }
            }
            if self.encoder.open {
                let req=self.io.req_base();let resp=self.io.resp_base();
                let mut log=IoLog;
                release_encoder_queues(&mut self.io.mmio,&mut self.io.q0,&req,&resp,
                    self.encoder.host_id,&mut self.encoder_slot,&mut log);
                let mut cfg=SessionConfig::empty();
                let _=close_session(&mut self.io.mmio,&mut self.io.q0,&req,&resp,
                    self.encoder.host_id,&mut cfg,200,&mut log);
                self.encoder.open=false;
            }
            if !self.io.mmio.common.is_null() {
                virtio_media::set_status(&mut self.io.mmio, 0);
                let _ = wdm::ke_delay_execution_thread(wdm::NtTime::relative_ms(100));
            }
            if !self.io.pool_va.is_null() {
                wdm::MmUnmapIoSpace(self.io.pool_va as *mut c_void, self.io.pool_len as u64);
            }
        }
    }
}

/// Wait for the ACPI `MEDIA_HOST` device to publish the pool. ACPI children
/// start independently; the PCI function may probe first.
pub(crate) fn wait_pool(_log: &mut dyn virtio_media::Log) -> Option<(u64, u64)> {
    for _ in 0..100 {
        let base = POOL_BASE.load(Ordering::SeqCst);
        let size = POOL_SIZE.load(Ordering::SeqCst);
        if base != 0 && size != 0 {
            return Some((base, size));
        }
        let _ = wdm::ke_delay_execution_thread(wdm::NtTime::relative_ms(50));
    }
    None
}

pub(crate) unsafe fn map_pool(
    base: u64,
    size: u64,
    log: &mut dyn virtio_media::Log,
) -> Option<*mut u8> {
    if size == 0 || size > POOL_MAX_BYTES {
        vlog(log, format_args!("media_host pool size 0x{:X} is outside the sane range", size));
        return None;
    }
    // 1.0.0.23 CACHED-POOL: map the pool **cached** -- it is RAM, and the reads
    // through this mapping (GET_FRAME's copy, and the user windows MAP_FRAME
    // builds over the same pages) are the 30 ms/frame bottleneck when it is
    // noncached.  `MmMapIoSpace` takes the MEMORY_CACHING_TYPE directly; the
    // pre-1.0.0.23 call was `MmMapIoSpaceEx(..., PAGE_READWRITE|PAGE_NOCACHE)`,
    // i.e. the same thing with MmNonCached.  Everything that reads through this
    // mapping now has to invalidate first (see the file's cache-maintenance
    // comment); everything that writes through it has to clean afterwards.
    let mut va = wdm::mm_map_io_space(base, size, wdm::MEMORY_CACHING_TYPE::MmCached)
        .map(|p| p.as_ptr() as *mut u8)
        .unwrap_or(ptr::null_mut());
    let mut cached = !va.is_null();
    if va.is_null() {
        // A platform that refuses a cached mapping of this range still has to
        // work: the noncached mapping is correct, just slow (no maintenance).
        vlog(
            log,
            format_args!("media_host pool MmCached refused, falling back to MmNonCached (slow path)"),
        );
        va = wdm::MmMapIoSpaceEx(
            wdm::PHYSICAL_ADDRESS { QuadPart: base as i64 },
            size,
            wdm::PAGE_READWRITE | wdm::PAGE_NOCACHE,
        ) as *mut u8;
        cached = false;
    }
    if va.is_null() {
        vlog(log, format_args!("MmMapIoSpaceEx(0x{:X}, 0x{:X}) failed for media_host", base, size));
        return None;
    }
    POOL_CACHED.store(cached, Ordering::SeqCst);
    vlog(
        log,
        format_args!(
            "media_host mapped: pa=0x{:X} len=0x{:X} -> va=0x{:X} cache={} (line={} B)",
            base,
            size,
            va as usize,
            if cached { "MmCached" } else { "MmNonCached" },
            data_cache_line_bytes()
        ),
    );
    Some(va)
}

/// One virtio-media command: header, payload, response. Returns the response
/// payload length (`used - RespHeader`) and copies the payload into `out`.
unsafe fn submit_req(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    req: &[u8],
    out: &mut [u8],
    max_spins: u32,
    log: &mut dyn virtio_media::Log,
) -> Result<usize, virtio_media::Error> {
    if req.len() > req_base.len || req.len() > u32::MAX as usize {
        return Err(virtio_media::Error::QueueMemorySmall(req.len(), req_base.len));
    }
    // A timed-out descriptor still owns its request DMA: never overwrite it.
    if mmio.poisoned() { return Err(virtio_media::Error::DeviceStatus(0xFF)); }
    virtio_media::write_buf(req_base, req);
    let req_buf = virtio_media::Buf { len: req.len(), ..*req_base };
    // P-BATCH MSI-X: the wait between used-ring looks is now an interrupt wait
    // (falls back to the 1.0.0.16 busy stall on its own).
    let dev = mmio.wdf_device;
    let mut stall = move || unsafe { irq::wait(dev) };
    let used = virtio_media::submit(mmio, q, &req_buf, resp, &mut stall, max_spins, log)?;
    let mut rbuf = [0u8; RESP_CAP];
    let got = virtio_media::read_buf(resp, &mut rbuf);
    let n = core::cmp::min(used, got);
    if n < 8 {
        vlog(log, format_args!("response is shorter than RespHeader ({} bytes)", n));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    let errno = i32::from_le_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]);
    if errno != 0 {
        vlog(log, format_args!("command failed: errno={} ({}) used={}", errno, -errno, used));
        return Err(virtio_media::Error::Errno(errno));
    }
    let plen = n - 8;
    let copy = core::cmp::min(plen, out.len());
    out[..copy].copy_from_slice(&rbuf[8..8 + copy]);
    Ok(plen)
}

/// `VIRTIO_MEDIA_CMD_IOCTL` with an opaque payload.
unsafe fn do_ioctl(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    code: u32,
    payload: &[u8],
    out: &mut [u8],
    log: &mut dyn virtio_media::Log,
) -> Result<usize, virtio_media::Error> {
    if 16 + payload.len() > req_base.len {
        return Err(virtio_media::Error::QueueMemorySmall(16 + payload.len(), req_base.len));
    }
    let mut req = [0u8; REQ_CAP];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_IOCTL);
    virtio_media::write_u32(&mut req, 8, session_id);
    virtio_media::write_u32(&mut req, 12, code);
    req[16..16 + payload.len()].copy_from_slice(payload);
    match submit_req(mmio, q, req_base, resp, &req[..16 + payload.len()], out, COMMAND_SPINS, log) {
        // Preserve both the ioctl code and the errno for the failure log.
        Err(virtio_media::Error::Errno(errno)) => {
            Err(virtio_media::Error::IoctlFailed(code, errno))
        }
        other => other,
    }
}

/// `VIRTIO_MEDIA_CMD_MMAP` returns (pool-relative offset, length).
unsafe fn do_mmap(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    offset: u32,
    log: &mut dyn virtio_media::Log,
) -> Result<(u64, u64), virtio_media::Error> {
    let mut req = [0u8; REQ_CAP];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_MMAP);
    virtio_media::write_u32(&mut req, 8, session_id);
    virtio_media::write_u32(&mut req, 12, virtio_media::VIRTIO_MEDIA_MMAP_FLAG_RW);
    virtio_media::write_u32(&mut req, 16, offset);
    let mut out = [0u8; 32];
    let n = submit_req(mmio, q, req_base, resp, &req[..20], &mut out, COMMAND_SPINS, log)?;
    if n < 16 {
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    Ok((virtio_media::read_u64(&out, 0), virtio_media::read_u64(&out, 8)))
}

fn build_fmt(
    fmt: &mut [u8; virtio_media::V4L2_FORMAT_SIZE],
    type_: u32,
    width: u32,
    height: u32,
    fourcc: u32,
    sizeimage: u32,
    bytesperline: u32,
) {
    *fmt = [0u8; virtio_media::V4L2_FORMAT_SIZE];
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_TYPE, type_);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_WIDTH, width);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_HEIGHT, height);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_PIXELFORMAT, fourcc);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_FIELD, virtio_media::V4L2_FIELD_NONE);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_SIZEIMAGE, sizeimage);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_BYTESPERLINE, bytesperline);
    virtio_media::write_u32(fmt, virtio_media::V4L2_FORMAT_NUM_PLANES, 1);
}

fn build_buffer(
    buf: &mut [u8],
    index: u32,
    type_: u32,
    memory: u32,
    bytesused: u32,
    offset: u32,
    planes: u32,
) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_INDEX, index);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_TYPE, type_);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_BYTESUSED, bytesused);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_FIELD, virtio_media::V4L2_FIELD_NONE);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_MEMORY, memory);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_OFFSET, offset);
    virtio_media::write_u32(buf, virtio_media::V4L2_BUFFER_LENGTH, planes);
}

/// Bits `0..n-1` set. `n` is a REQBUFS count (<= MAX_OUTPUT_BUFS / 32).
fn mask_bits(n: u32) -> u32 {
    if n >= 32 {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

fn log_fmt(what: &str, out: &[u8], log: &mut dyn virtio_media::Log) {
    if out.len() < virtio_media::V4L2_FORMAT_SIZE {
        return;
    }
    let pixel = virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_PIXELFORMAT);
    let fcc = fourcc(pixel);
    let fcc = core::str::from_utf8(&fcc).unwrap_or("????");
    vlog(
        log,
        format_args!(
            "{}: {}x{} fourcc=0x{:08X} ('{}') sizeimage={} stride={} num_planes={}",
            what,
            virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_WIDTH),
            virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_HEIGHT),
            pixel,
            fcc,
            virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_SIZEIMAGE),
            virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_BYTESPERLINE),
            virtio_media::read_u32(out, virtio_media::V4L2_FORMAT_NUM_PLANES),
        ),
    );
}

unsafe fn streamon(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    type_: u32,
    what: &str,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let mut payload = [0u8; 4];
    virtio_media::write_u32(&mut payload, 0, type_);
    let mut out = [0u8; 16];
    do_ioctl(
        mmio,
        q,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_IOCTL_STREAMON,
        &payload,
        &mut out,
        log,
    )?;
    vlog(log, format_args!("STREAMON {} ok", what));
    Ok(())
}

unsafe fn qbuf(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    type_: u32,
    index: u32,
    mem_offset: u32,
    sizeimage: u32,
    bytesused: u32,
    tag: u64,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let mut req = [0u8; REQ_CAP];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_IOCTL);
    virtio_media::write_u32(&mut req, 8, session_id);
    virtio_media::write_u32(&mut req, 12, virtio_media::V4L2_IOCTL_QBUF);
    let base = 16;
    build_buffer(
        &mut req[base..base + virtio_media::V4L2_BUFFER_SIZE],
        index,
        type_,
        virtio_media::V4L2_MEMORY_MMAP,
        bytesused,
        mem_offset,
        1,
    );
    let tag = if virtio_media::read_u32(&req, base + virtio_media::V4L2_BUFFER_TYPE) == virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE { tag } else { 0 };
    virtio_media::write_u64(&mut req, base + virtio_media::V4L2_BUFFER_TIMESTAMP, tag / 1_000_000);
    virtio_media::write_u64(&mut req, base + virtio_media::V4L2_BUFFER_TIMESTAMP + 8, tag % 1_000_000);
    let plane = base + virtio_media::V4L2_BUFFER_SIZE;
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_BYTESUSED, bytesused);
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_LENGTH, sizeimage);
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_OFFSET, mem_offset);
    let len = base + virtio_media::V4L2_BUFFER_SIZE + virtio_media::V4L2_PLANE_SIZE;
    let mut out = [0u8; 256];
    submit_req(mmio, q, req_base, resp, &req[..len], &mut out, COMMAND_SPINS, log)?;
    Ok(())
}

/// 1.0.0.12 diagnostics: milliseconds since `t0` (QPC), 0.0 if the counter is
/// unavailable.  Cheap enough to call a few times per access unit, and the
/// caller logs only every 30th.
fn qpc_now() -> u64 {
    wdm::ke_query_performance_counter().0
}

fn qpc_ms_since(t0: u64) -> f64 {
    qpc_ms_between(t0, qpc_now())
}

fn qpc_ms_between(t0: u64, t1: u64) -> f64 {
    let (_, freq) = wdm::ke_query_performance_counter();
    if freq == 0 || t1 < t0 {
        return 0.0;
    }
    (t1 - t0) as f64 * 1000.0 / freq as f64
}

/// Microseconds are the interesting unit for the per-frame cache maintenance
/// (a 3.1 MB invalidate is tens of them), so log that in µs directly.
fn qpc_us_between(t0: u64, t1: u64) -> f64 {
    let (_, freq) = wdm::ke_query_performance_counter();
    if freq == 0 || t1 < t0 {
        return 0.0;
    }
    (t1 - t0) as f64 * 1_000_000.0 / freq as f64
}

/// Queue one OUTPUT buffer (one access unit) on the command queue **without
/// waiting for the device to accept it** (P3-6 / 1.0.0.12, the pipelining fix).
///
/// Why this is the fix for 1080p: the host decoder does the whole decode
/// synchronously inside the `QBUF(OUTPUT)` handler (crosvm's ffmpeg backend
/// calls `try_decode()` from `decode()`), so a synchronous QBUF answers only
/// after a full frame has been decoded.  The client then waits *again* for the
/// frame to appear on the event queue.  At 1920x1088 that is 30.4 ms + 32.8 ms
/// per access unit = 63-68 ms, i.e. the 16.33 fps E147 measured.  Handing the
/// AU to the ring and returning makes the client's SEND ~free, so the period
/// becomes the decode time alone (~33 ms -> ~30 fps) instead of twice it.
///
/// The answer is collected by the next synchronous command (`submit` reaps
/// first, see `virtio_media::reap_async`) and a refused QBUF is logged there and
/// remembered in `Queue::async_err`.
unsafe fn qbuf_async(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    session_id: u32,
    cfg: &SessionConfig,
    index: u32,
    bytesused: u32,
    owner: u8,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let i = index as usize;
    let mut req = [0u8; REQ_CAP];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_IOCTL);
    virtio_media::write_u32(&mut req, 8, session_id);
    virtio_media::write_u32(&mut req, 12, virtio_media::V4L2_IOCTL_QBUF);
    let base = 16;
    build_buffer(
        &mut req[base..base + virtio_media::V4L2_BUFFER_SIZE],
        index,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        virtio_media::V4L2_MEMORY_MMAP,
        bytesused,
        cfg.out_off[i],
        1,
    );
    let tag = if virtio_media::read_u32(&req, base + virtio_media::V4L2_BUFFER_TYPE) == virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE { cfg.send_tag } else { 0 };
    virtio_media::write_u64(&mut req, base + virtio_media::V4L2_BUFFER_TIMESTAMP, tag / 1_000_000);
    virtio_media::write_u64(&mut req, base + virtio_media::V4L2_BUFFER_TIMESTAMP + 8, tag % 1_000_000);
    let plane = base + virtio_media::V4L2_BUFFER_SIZE;
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_BYTESUSED, bytesused);
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_LENGTH, cfg.out_len[i]);
    virtio_media::write_u32(&mut req, plane + virtio_media::V4L2_PLANE_OFFSET, cfg.out_off[i]);
    let len = base + virtio_media::V4L2_BUFFER_SIZE + virtio_media::V4L2_PLANE_SIZE;
    let dev = mmio.wdf_device;
    let mut stall = move || unsafe { irq::wait(dev) };
    virtio_media::submit_async(mmio, q0, &req[..len], &mut stall, COMMAND_SPINS, owner, log)?;
    Ok(())
}

/// Give a decoded CAPTURE buffer back to the device so it can be filled again.
pub(crate) unsafe fn requeue_capture(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    cfg: &mut SessionConfig,
    index: usize,
    log: &mut dyn virtio_media::Log,
) {
    let bit = 1u32 << index.min(31);
    match qbuf(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        index as u32,
        cfg.cap_off[index],
        cfg.cap_len[index],
        0,
        0,
        log,
    ) {
        Ok(()) => cfg.cap_queued |= bit,
        Err(e) => {
            cfg.cap_queued &= !bit;
            vlog(
                log,
                format_args!(
                    "capture[{}] re-QBUF failed: {} (the CAPTURE queue loses one buffer)",
                    index, e.text()
                ),
            );
        }
    }
}

/// `VIRTIO_MEDIA_CMD_OPEN`; returns the device's session id (0 is valid).
pub(crate) unsafe fn open_session(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    log: &mut dyn virtio_media::Log,
) -> Result<u32, virtio_media::Error> {
    let open_req: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    let mut out = [0u8; 16];
    vlog(log, format_args!("request: VIRTIO_MEDIA_CMD_OPEN (cmd=1, 8 bytes)"));
    let n = submit_req(mmio, q0, req_base, resp, &open_req, &mut out, COMMAND_SPINS, log)?;
    if n < 4 {
        vlog(log, format_args!("OPEN response payload is too short ({} bytes)", n));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    let session_id = virtio_media::read_u32(&out, 0);
    vlog(log, format_args!("OPEN OK: session_id={} (response payload {} bytes)", session_id, n));
    Ok(session_id)
}

/// `VIRTIO_MEDIA_CMD_MUNMAP`: give one pool mapping back to the VMM.
///
/// The device's `HostMemoryMapper::add_mapping` carves each MMAP out of the
/// `media_host` pool's address allocator and only `remove_mapping` (= this
/// command) gives the range back.  Closing a session does *not* release them, so
/// a driver that only sends CLOSE leaks `capture_count * sizeimage` (≈26 MiB for
/// 20 NV12 frames at 720p) per session; after two sessions REQBUFS answers
/// ENOMEM and nothing decodes again until the device is reset.  P2-2f.
pub(crate) unsafe fn do_munmap(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    driver_addr: u64,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    // CmdHeader { cmd, padding } (8 bytes) + MunmapCmd { driver_addr } (8 bytes).
    let mut req = [0u8; 16];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_MUNMAP);
    virtio_media::write_u64(&mut req, 8, driver_addr);
    let mut out = [0u8; 8];
    submit_req(mmio, q, req_base, resp, &req, &mut out, COMMAND_SPINS, log)?;
    Ok(())
}

/// How many pool ranges `cfg` still owes a MUNMAP for.
pub(crate) fn pending_mappings(cfg: &SessionConfig) -> u32 {
    cfg.cap_mapped.count_ones() + cfg.out_mapped.count_ones()
}

/// Release every pool mapping `cfg` still holds and clear its bookkeeping, so a
/// second call is a no-op (the OPEN path relies on that).
///
/// The walk is driven by [`SessionConfig::cap_mapped`] / `out_mapped`, not by
/// `addr != 0`: the first mapping of a session legitimately answers pool offset
/// 0, and 1.0.0.11 skipped it -- one 3.13 MiB 1080p capture buffer stayed mapped
/// (and its host backing stayed in the device's retired list) for the lifetime of
/// the device, so the next 1080p session's `REQBUFS` came back ENOMEM.  E148.
///
/// Best effort: a failed MUNMAP is logged and the bit is still cleared, because
/// the address is meaningless once the session is gone and a retry would only
/// produce a second failure.
unsafe fn release_mappings(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> u32 {
    let cap_mask = cfg.cap_mapped;
    let out_mask = cfg.out_mapped;
    let cap_count = core::cmp::min(cfg.capture_count as usize, MAX_CAPTURE_BUFS);
    let out_count = core::cmp::min(cfg.output_count as usize, MAX_OUTPUT_BUFS);
    let mut released = 0u32;
    let mut failed = 0u32;
    for i in 0..cap_count {
        if cap_mask & (1u32 << i) == 0 {
            continue;
        }
        let addr = cfg.cap_addr[i];
        match do_munmap(mmio, q, req_base, resp, addr, log) {
            Ok(()) => released += 1,
            Err(e) => {
                failed += 1;
                vlog(
                    log,
                    format_args!("MUNMAP capture[{}] addr=0x{:X} failed: {}", i, addr, e.text()),
                );
            }
        }
        cfg.cap_mapped &= !(1u32 << i);
    }
    for i in 0..out_count {
        if out_mask & (1u32 << i) == 0 {
            continue;
        }
        let addr = cfg.out_addr[i];
        match do_munmap(mmio, q, req_base, resp, addr, log) {
            Ok(()) => released += 1,
            Err(e) => {
                failed += 1;
                vlog(
                    log,
                    format_args!("MUNMAP output[{}] addr=0x{:X} failed: {}", i, addr, e.text()),
                );
            }
        }
        cfg.out_mapped &= !(1u32 << i);
    }
    let owed = pending_mappings(cfg);
    if released != 0 || failed != 0 || cap_mask != 0 || out_mask != 0 {
        vlog(
            log,
            format_args!(
                "pool mappings released: {} ok, {} failed ({} capture + {} output owed); pool mappings left: {}",
                released,
                failed,
                cap_mask.count_ones(),
                out_mask.count_ones(),
                owed
            ),
        );
    }
    released
}

/// Drop every pool range this device still has mapped, whether or not a session
/// is open. Called from OPEN before it opens a fresh session, so a client that
/// died without CLOSE cannot leave the pool short (idempotent).
pub(crate) unsafe fn release_all_mappings(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> u32 {
    let owed = pending_mappings(cfg);
    if owed == 0 {
        return 0;
    }
    vlog(log, format_args!("pool sweep: {} mapping(s) still owed a MUNMAP, releasing", owed));
    release_mappings(mmio, q, req_base, resp, cfg, log)
}

/// `REQBUFS(type, count = 0)`: free whatever the host's queue still holds.
///
/// V4L2 defines count 0 as "release this queue's buffers", and it is the only
/// way to give back the buffers an *interrupted* `REQBUFS` managed to allocate
/// before the media_host pool refused the rest.  Nothing was MMAP'd for those
/// buffers, so `MUNMAP` cannot reach them; without this they stay charged to the
/// pool for the life of the device and every later session -- whatever its codec
/// or resolution -- fails with ENOMEM (E172: AV1 left the pool short, then
/// H.264 720p failed 574 times in the same boot).
///
/// Best effort: callers are already on an error path, and a queue that never
/// held anything answers this with an error that is equally harmless.
unsafe fn free_queue(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    type_: u32,
    what: &str,
    log: &mut dyn virtio_media::Log,
) {
    let mut rb = [0u8; virtio_media::V4L2_REQBUFS_SIZE];
    virtio_media::write_u32(&mut rb, 0, 0);
    virtio_media::write_u32(&mut rb, 4, type_);
    virtio_media::write_u32(&mut rb, 8, virtio_media::V4L2_MEMORY_MMAP);
    let mut out = [0u8; 256];
    match do_ioctl(
        mmio, q, req_base, resp, session_id, virtio_media::V4L2_IOCTL_REQBUFS, &rb, &mut out, log,
    ) {
        Ok(_) => vlog(log, format_args!("REQBUFS {}: queue freed (count 0)", what)),
        Err(e) => vlog(
            log,
            format_args!("REQBUFS {}: count 0 returned {} (queue was already empty)", what, e.text()),
        ),
    }
}

/// `STREAMOFF(type)`, best effort.
///
/// V4L2 answers `EBUSY` to `REQBUFS(0)` on a queue that is still streaming, and
/// a configure that failed on the *second* `STREAMON` leaves the first queue
/// streaming.  The rollback therefore stops both queues before it frees them.
unsafe fn streamoff(
    mmio: &mut Kmmio,
    q: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    type_: u32,
    what: &str,
    log: &mut dyn virtio_media::Log,
) {
    let mut payload = [0u8; 4];
    virtio_media::write_u32(&mut payload, 0, type_);
    let mut out = [0u8; 16];
    match do_ioctl(
        mmio,
        q,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_IOCTL_STREAMOFF,
        &payload,
        &mut out,
        log,
    ) {
        Ok(_) => vlog(log, format_args!("STREAMOFF {} ok (rollback)", what)),
        Err(e) => vlog(
            log,
            format_args!("STREAMOFF {} returned {} (rollback continues)", what, e.text()),
        ),
    }
}

/// Undo a failed configure: stop both queues, give every pool mapping back, free
/// both queues, and leave `cfg` empty so the next attempt starts from scratch.
///
/// 1.0.0.20 / E173.  1.0.0.19 logged "N mapping(s) still owed" and trusted
/// CLOSE/OPEN to clean up, but a client that keeps retrying SEND never reaches
/// either: the UMD calls SEND once per access unit, and each failed configure
/// used to `SessionConfig::empty()` the bookkeeping before retrying, so the
/// partial `REQBUFS` allocation and any mapped range were unreachable.  That is
/// the "poisoned session" E172 measured.
///
/// Returns how many mappings this call actually released (for the log).
pub(crate) unsafe fn rollback_configure(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> u32 {
    streamoff(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        "CAPTURE",
        log,
    );
    streamoff(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        "OUTPUT",
        log,
    );
    // Mappings first: while one exists the host must keep its pool range.
    let released = release_mappings(mmio, q0, req_base, resp, cfg, log);
    free_queue(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        "CAPTURE",
        log,
    );
    free_queue(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        "OUTPUT",
        log,
    );
    cfg.capture_count = 0;
    cfg.output_count = 0;
    cfg.cap_queued = 0;
    cfg.out_free = 0;
    cfg.configured = false;
    vlog(
        log,
        format_args!(
            "rollback: session {} left clean ({} mapping(s) released, both queues freed, 0 owed)",
            session_id, released
        ),
    );
    released
}

/// Send `VIRTIO_MEDIA_CMD_CLOSE` for one session.
///
/// The on-the-wire request is `CmdHeader { cmd, padding }` (8 bytes) **followed
/// by** `CloseCmd { session_id, padding }` (8 bytes), i.e. 16 bytes.
/// P2-1d wrote only 8 bytes -- the session id landed in `CmdHeader.padding` --
/// so the host's `read_obj::<CloseCmd>()` ran out of bytes, answered `EINVAL`
/// (22) *without* removing the session, and the guest kept
/// `LiveState::session_open` set.  Every later OPEN then failed with
/// `STATUS_INVALID_DEVICE_STATE`, which is the `err=22` wedge P2-2e hit in Edge
/// (and which only `pnputil /restart-device` could clear).  P2-2f.
///
/// CLOSE is also the one command the host answers with **no payload at all**
/// (`VIRTIO_MEDIA_CMD_CLOSE` has no `write_response`), so a used entry of length
/// 0 means success, not a truncated response.
///
/// `cfg` is the session's mapping bookkeeping: its pool ranges are MUNMAP'd
/// before the session goes away, otherwise the media_host pool leaks (P2-2f).
pub(crate) unsafe fn close_session(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    cfg: &mut SessionConfig,
    max_spins: u32,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let _ = release_mappings(mmio, q0, req_base, resp, cfg, log);
    const CLOSE_REQ_LEN: usize = 16;
    if CLOSE_REQ_LEN > req_base.len {
        return Err(virtio_media::Error::QueueMemorySmall(CLOSE_REQ_LEN, req_base.len));
    }
    let mut req = [0u8; CLOSE_REQ_LEN];
    virtio_media::write_u32(&mut req, 0, virtio_media::MEDIA_CMD_CLOSE);
    virtio_media::write_u32(&mut req, 8, session_id);
    if mmio.poisoned() { return Err(virtio_media::Error::DeviceStatus(0xFF)); }
    virtio_media::write_buf(req_base, &req);
    let req_buf = virtio_media::Buf { len: CLOSE_REQ_LEN, ..*req_base };
    let dev = mmio.wdf_device;
    let mut stall = move || unsafe { irq::wait(dev) };
    let used = virtio_media::submit(mmio, q0, &req_buf, resp, &mut stall, max_spins, log)?;
    if used == 0 {
        vlog(log, format_args!("CLOSE session {} ok (device answered without a payload)", session_id));
        return Ok(());
    }
    let mut rbuf = [0u8; RESP_CAP];
    let got = virtio_media::read_buf(resp, &mut rbuf);
    let n = core::cmp::min(used, got);
    if n >= 8 {
        let errno = i32::from_le_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]);
        if errno != 0 {
            vlog(
                log,
                format_args!("CLOSE session {} refused by the device: errno={} ({})", session_id, errno, -errno),
            );
            return Err(virtio_media::Error::Errno(errno));
        }
    }
    vlog(log, format_args!("CLOSE session {} ok (response payload {} bytes)", session_id, n.saturating_sub(8)));
    Ok(())
}

/// The OUTPUT fourcc and the human name of a session's coded format, from
/// `VM_OPEN_IN.Codec` (P-BATCH VP9 / HEVC / AV1, HEVC-MAIN10).
pub(crate) fn codec_fourcc(codec: u32) -> (u32, &'static str) {
    match codec {
        vmedia_abi::VM_OPEN_CODEC_VP9 => (virtio_media::V4L2_PIX_FMT_VP9, "VP9"),
        vmedia_abi::VM_OPEN_CODEC_HEVC => (virtio_media::V4L2_PIX_FMT_HEVC, "HEVC"),
        // HEVC-MAIN10: Main10 is the *same* coded format and the same host
        // decoder as Main; only the CAPTURE side changes (P010 instead of NV12).
        vmedia_abi::VM_OPEN_CODEC_HEVC_MAIN10 => {
            (virtio_media::V4L2_PIX_FMT_HEVC, "HEVC Main10")
        }
        vmedia_abi::VM_OPEN_CODEC_AV1 => (virtio_media::V4L2_PIX_FMT_AV1, "AV1"),
        _ => (virtio_media::V4L2_PIX_FMT_H264, "H.264"),
    }
}

/// HEVC-MAIN10: the sample depth a session was opened for, from
/// `VM_OPEN_IN.Codec`.  This is the *requested* depth; what the capture queue
/// really carries is `SessionConfig::capture_bit_depth` after S_FMT.
pub(crate) fn codec_bit_depth(codec: u32) -> u32 {
    if codec == vmedia_abi::VM_OPEN_CODEC_HEVC_MAIN10 {
        10
    } else {
        8
    }
}

/// Bytes per sample of a CAPTURE fourcc: 1 for the 8-bit NV12 layout, 2 for the
/// 10-bit-in-16-bit-words P010 layout.  Everything that turns a width into a row
/// length (sizeimage, stride, the tight frame size, the row copy) goes through
/// this, so the two layouts differ in exactly one number.
pub(crate) fn capture_bytes_per_sample(fourcc: u32) -> u32 {
    if fourcc == virtio_media::V4L2_PIX_FMT_P010 {
        2
    } else {
        1
    }
}

/// Human name of a CAPTURE fourcc (the frame layouts GET_FRAME reports).
pub(crate) fn capture_fourcc_name(fourcc: u32) -> &'static str {
    if fourcc == virtio_media::V4L2_PIX_FMT_P010 {
        "P010"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_NV12 {
        "NV12"
    } else {
        "other"
    }
}

/// Human name of an OUTPUT fourcc, for the log lines that report what the device
/// accepted.
pub(crate) fn fourcc_name(fourcc: u32) -> &'static str {
    if fourcc == virtio_media::V4L2_PIX_FMT_VP9 {
        "VP90"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_HEVC {
        "HEVC"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_AV1 {
        "AV01"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_H264 {
        "H264"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_NV12 {
        "NV12"
    } else if fourcc == virtio_media::V4L2_PIX_FMT_P010 {
        "P010"
    } else {
        "other"
    }
}

/// Configure the decoder, fill output[0] with `bitstream`, queue everything and
/// start both streams. This is P1d's proven sequence, with the data supplied
/// by the caller.
///
/// `codec` is `VM_OPEN_IN.Codec` of the session (P-BATCH VP9 / HEVC / AV1).  It
/// selects the OUTPUT pixel format, i.e. which host decoder the virtio-media
/// device configures: 'H264' -> c2.qti.avc.decoder, 'VP90' ->
/// c2.qti.vp9.decoder, 'HEVC' -> c2.qti.hevc.decoder, 'AV01' ->
/// c2.qti.av1.decoder.  The capture side stays
/// NV12 for all three.
///
/// 1.0.0.20 / E173: **any** failure here is rolled back before it reaches the
/// caller (`rollback_configure`: STREAMOFF both queues, MUNMAP every range,
/// `REQBUFS(0)` both queues).  A client retries SEND once per access unit on the
/// Negotiate encoder queue formats in the V4L2 reverse direction: NV12 enters
/// OUTPUT and encoded H.264 leaves CAPTURE.
pub(crate) unsafe fn configure_encoder_formats(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    host_id: u32,
    config: &vmedia_abi::VM_ENCODER_CONFIG,
    log: &mut dyn virtio_media::Log,
) -> Result<(u32, u32, u32), virtio_media::Error> {
    let mut fmt = [0u8; virtio_media::V4L2_FORMAT_SIZE];
    let mut out = [0u8; 256];
    build_fmt(
        &mut fmt,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        config.Width,
        config.Height,
        virtio_media::V4L2_PIX_FMT_NV12,
        0,
        config.YStride,
    );
    let used = do_ioctl(
        mmio, q0, req_base, resp, host_id, virtio_media::V4L2_IOCTL_S_FMT,
        &fmt, &mut out, log,
    )?;
    if crate::encoder_abi::validate_format_reply_len(used,virtio_media::V4L2_FORMAT_SIZE).is_err(){return Err(virtio_media::Error::DeviceStatus(0));}
    let width = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_WIDTH);
    let height = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_HEIGHT);
    if crate::encoder_abi::validate_negotiated_dimensions(config, width, height).is_err() {
        vlog(log, format_args!("ENC S_FMT OUTPUT dimensions changed: requested={}x{} negotiated={}x{}", config.Width, config.Height, width, height));
        return Err(virtio_media::Error::Errno(22));
    }
    let input_fourcc = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_PIXELFORMAT);
    let input_size = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_SIZEIMAGE);
    let input_stride = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_BYTESPERLINE);
    if input_fourcc != virtio_media::V4L2_PIX_FMT_NV12
        || input_stride < config.YStride
        || input_size == 0
    {
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    build_fmt(
        &mut fmt,
        virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        config.Width,
        config.Height,
        virtio_media::V4L2_PIX_FMT_H264,
        0,
        0,
    );
    let used = do_ioctl(
        mmio, q0, req_base, resp, host_id, virtio_media::V4L2_IOCTL_S_FMT,
        &fmt, &mut out, log,
    )?;
    if crate::encoder_abi::validate_format_reply_len(used,virtio_media::V4L2_FORMAT_SIZE).is_err(){return Err(virtio_media::Error::DeviceStatus(0));}
    let width = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_WIDTH);
    let height = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_HEIGHT);
    if crate::encoder_abi::validate_negotiated_dimensions(config, width, height).is_err() {
        vlog(log, format_args!("ENC S_FMT CAPTURE dimensions changed: requested={}x{} negotiated={}x{}", config.Width, config.Height, width, height));
        return Err(virtio_media::Error::Errno(22));
    }
    let output_fourcc = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_PIXELFORMAT);
    let output_size = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_SIZEIMAGE);
    if output_fourcc != virtio_media::V4L2_PIX_FMT_H264 || output_size == 0 {
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    vlog(log, format_args!(
        "ENC S_FMT: OUTPUT NV12 stride={} sizeimage={} / CAPTURE H264 sizeimage={}",
        input_stride, input_size, output_size
    ));
    Ok((input_stride, input_size, output_size))
}

/// Configure the encoder's reverse-direction V4L2 queues and map each host
/// resource through the already mapped media-host pool. No decoder SessionConfig
/// or decoder queue bitfield is shared here.
pub(crate) unsafe fn release_encoder_queues(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,req:&virtio_media::Buf,resp:&virtio_media::Buf,
    host_id:u32,state:&mut crate::encoder_state::EncoderSlot,log:&mut dyn virtio_media::Log,
){
    reset_encoder_queues(mmio,q0,req,resp,host_id,state,log);
    state.abort_configure();
}

pub(crate) unsafe fn reset_encoder_queues(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,req:&virtio_media::Buf,resp:&virtio_media::Buf,
    host_id:u32,state:&mut crate::encoder_state::EncoderSlot,log:&mut dyn virtio_media::Log,
){
    if let Some(queues)=state.queue_config(){
        if queues.streamon_mask&1!=0{streamoff(mmio,q0,req,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,"encoder OUTPUT",log)}
        if queues.streamon_mask&2!=0{streamoff(mmio,q0,req,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,"encoder CAPTURE",log)}
        while let Some(range)=state.take_pool_range(){let _=do_munmap(mmio,q0,req,resp,range.driver_addr,log);}
        free_queue(mmio,q0,req,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,"encoder CAPTURE",log);
        free_queue(mmio,q0,req,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,"encoder OUTPUT",log);
    }
}

pub(crate) unsafe fn requeue_encoder_capture(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,req:&virtio_media::Buf,resp:&virtio_media::Buf,
    host:u32,state:&crate::encoder_state::EncoderSlot,index:u32,log:&mut dyn virtio_media::Log,
)->Result<(),virtio_media::Error>{
    let q=state.queue_config().ok_or(virtio_media::Error::DeviceStatus(0))?;
    if index>=q.output_count{return Err(virtio_media::Error::EventIndex(index))}
    let range=state.pool_range(index,1).ok_or(virtio_media::Error::EventIndex(index))?;
    qbuf(mmio,q0,req,resp,host,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        index,range.mem_offset,range.buffer_len,0,0,log)
}

pub(crate) unsafe fn queue_encoder_input(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,host_id:u32,
    req_base:&virtio_media::Buf,resp:&virtio_media::Buf,pool_va:*mut u8,pool_len:usize,
    state:&mut crate::encoder_state::EncoderSlot,frame:&vmedia_abi::VM_ENCODER_INPUT,
    payload:&[u8],log:&mut dyn virtio_media::Log,
)->Result<(),virtio_media::Error>{
    let force=frame.Flags&vmedia_abi::VM_ENCODER_INPUT_FORCE_KEYFRAME!=0;
    // Before the first OUTPUT STREAMON the backend consumes this button without
    // saving it; the first frame is already an IDR. Later requests must precede QBUF.
    let started=state.queue_config().map(|q|q.streamon_mask&1!=0).unwrap_or(false);
    state.queue_input(frame,payload.len()).map_err(|_|virtio_media::Error::Errno(22))?;
    let Some(slot)=state.input_slot(frame.BufferId)else{return Err(virtio_media::Error::Errno(22))};
    let Some(range)=state.pool_range(slot,0)else{let _=state.cancel_input(frame.BufferId);return Err(virtio_media::Error::Errno(22))};
    if payload.len()>range.buffer_len as usize||range.offset>pool_len as u64||payload.len()>pool_len.saturating_sub(range.offset as usize){
        let _=state.cancel_input(frame.BufferId);return Err(virtio_media::Error::Errno(22));
    }
    let dst=unsafe{pool_va.add(range.offset as usize)};
    unsafe{ptr::copy_nonoverlapping(payload.as_ptr(),dst,payload.len())};
    if POOL_CACHED.load(Ordering::SeqCst){cache_clean_invalidate_range(dst,payload.len())}
    let mut req=[0u8;REQ_CAP];
    virtio_media::write_u32(&mut req,0,virtio_media::MEDIA_CMD_IOCTL);
    virtio_media::write_u32(&mut req,8,host_id);
    virtio_media::write_u32(&mut req,12,virtio_media::V4L2_IOCTL_QBUF);
    let base=16;
    build_buffer(&mut req[base..base+virtio_media::V4L2_BUFFER_SIZE],slot,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,virtio_media::V4L2_MEMORY_MMAP,
        payload.len() as u32,range.mem_offset,1);
    virtio_media::write_u32(&mut req,base+virtio_media::V4L2_BUFFER_FLAGS,virtio_media::V4L2_BUF_FLAG_TIMESTAMP_COPY);
    let ticks=frame.Timestamp;let sec=ticks/10_000_000;let usec=(ticks%10_000_000)/10;
    virtio_media::write_u64(&mut req,base+virtio_media::V4L2_BUFFER_TIMESTAMP,sec);
    virtio_media::write_u64(&mut req,base+virtio_media::V4L2_BUFFER_TIMESTAMP+8,usec);
    let plane=base+virtio_media::V4L2_BUFFER_SIZE;
    virtio_media::write_u32(&mut req,plane+virtio_media::V4L2_PLANE_BYTESUSED,payload.len() as u32);
    virtio_media::write_u32(&mut req,plane+virtio_media::V4L2_PLANE_LENGTH,range.buffer_len);
    virtio_media::write_u32(&mut req,plane+virtio_media::V4L2_PLANE_OFFSET,range.mem_offset);
    if force&&started {
        if let Err(e)=encoder_set_control(mmio,q0,req_base,resp,host_id,0x009909E5,0,log){
            let _=state.cancel_input(frame.BufferId);return Err(e)
        }
    }
    let mut out=[0u8;256];
    if let Err(e)=do_ioctl(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_IOCTL_QBUF,
        &req[16..base+virtio_media::V4L2_BUFFER_SIZE+virtio_media::V4L2_PLANE_SIZE],&mut out,log){
        let _=state.cancel_input(frame.BufferId);return Err(e)
    }
    let needs_streamon=state.queue_config().map(|q|q.streamon_mask&1==0).unwrap_or(true);
    if needs_streamon{
        if let Err(error)=streamon(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,"encoder OUTPUT",log){
            let _=state.cancel_input(frame.BufferId);
            reset_encoder_queues(mmio,q0,req_base,resp,host_id,state,log);
            state.abort_configure();
            return Err(error)
        }
        if state.mark_input_streaming().is_err(){
            reset_encoder_queues(mmio,q0,req_base,resp,host_id,state,log);
            state.abort_configure();
            return Err(virtio_media::Error::DeviceStatus(0))
        }
    }
    Ok(())
}

/// Apply startup controls before either queue can start the codec. Require the
/// echoed value to equal the request rather than silently accepting clamping.
pub(crate) unsafe fn encoder_set_control(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,req:&virtio_media::Buf,
    resp:&virtio_media::Buf,host:u32,id:u32,value:u32,log:&mut dyn virtio_media::Log,
)->Result<(),virtio_media::Error>{
    if value>i32::MAX as u32{return Err(virtio_media::Error::Errno(22))}
    let mut control=[0u8;8];let mut out=[0u8;8];
    virtio_media::write_u32(&mut control,0,id);virtio_media::write_u32(&mut control,4,value);
    let n=do_ioctl(mmio,q0,req,resp,host,virtio_media::V4L2_IOCTL_S_CTRL,&control,&mut out,log)?;
    if n<8||virtio_media::read_u32(&out,0)!=id||virtio_media::read_u32(&out,4)!=value{
        return Err(virtio_media::Error::Errno(22));
    }
    vlog(log,format_args!("ENCODER S_CTRL applied id=0x{:X} value={}",id,value));
    Ok(())
}

pub(crate) unsafe fn configure_encoder_queues(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    host_id: u32,
    pool_va: *mut u8,
    pool_size: usize,
    pool_budget: usize,
    config: &vmedia_abi::VM_ENCODER_CONFIG,
    input_limit: u32,
    output_limit: u32,
    state: &mut crate::encoder_state::EncoderSlot,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    if pool_va.is_null() || pool_size == 0 || pool_budget == 0 {
        return Err(virtio_media::Error::PoolMissing);
    }
    let (input_stride, input_size, output_size) =
        configure_encoder_formats(mmio, q0, req_base, resp, host_id, config, log)?;
    // V4L2_CID_CODEC_BASE=0x00990900. Both controls are startup parameters.
    encoder_set_control(mmio,q0,req_base,resp,host_id,0x009909CE,
        if config.Flags&vmedia_abi::VM_ENCODER_CONFIG_CBR!=0{1}else{0},log)?;
    encoder_set_control(mmio,q0,req_base,resp,host_id,0x009909CF,config.Bitrate,log)?;
    encoder_set_control(mmio,q0,req_base,resp,host_id,0x009909CB,config.GopFrames,log)?;
    // v4l2_streamparm: type4 + union200; timeperframe is at offset 12.
    let mut parm=[0u8;204];let mut parm_out=[0u8;204];
    virtio_media::write_u32(&mut parm,0,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
    virtio_media::write_u32(&mut parm,12,config.FrameRateDen);
    virtio_media::write_u32(&mut parm,16,config.FrameRateNum);
    let n=do_ioctl(mmio,q0,req_base,resp,host_id,22,&parm,&mut parm_out,log)?;
    let actual_den=virtio_media::read_u32(&parm_out,12);let actual_num=virtio_media::read_u32(&parm_out,16);
    if n<204||virtio_media::read_u32(&parm_out,0)!=virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE||
       (actual_den as u64)*(config.FrameRateNum as u64)!=(actual_num as u64)*(config.FrameRateDen as u64){
        return Err(virtio_media::Error::Errno(22));
    }
    state.set_negotiated_formats(input_stride,input_size,output_size)
        .map_err(|_|virtio_media::Error::DeviceStatus(0))?;
    let per_pair = (input_size as usize)
        .checked_add(output_size as usize)
        .ok_or(virtio_media::Error::Errno(12))?;
    if per_pair == 0 { return Err(virtio_media::Error::Errno(12)); }
    let fit = (pool_budget / per_pair).min(input_limit as usize).min(output_limit as usize);
    let ask = fit.min(4) as u32;
    if ask < 2 { return Err(virtio_media::Error::Errno(12)); }

    let mut ranges = crate::encoder_state::EncoderPoolRanges::new(pool_size as u64);
    let mut allocated_input = false;
    let mut allocated_output = false;
    let mut input_count = 0u32;
    let mut output_count = 0u32;
    let mut streamon_mask = 0u8;
    let result = (|| {
        let mut rb = [0u8; virtio_media::V4L2_REQBUFS_SIZE];
        let mut out = [0u8; 256];
        virtio_media::write_u32(&mut rb, 0, ask);
        virtio_media::write_u32(&mut rb, 4, virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
        virtio_media::write_u32(&mut rb, 8, virtio_media::V4L2_MEMORY_MMAP);
        allocated_input = true;
        do_ioctl(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_IOCTL_REQBUFS,&rb,&mut out,log)?;
        input_count = virtio_media::read_u32(&out,0);
        if input_count < 2 || input_count > input_limit || input_count as usize > crate::encoder_state::MAX_ENCODER_INPUTS {
            return Err(virtio_media::Error::Errno(12));
        }
        virtio_media::write_u32(&mut rb, 0, ask);
        virtio_media::write_u32(&mut rb, 4, virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
        allocated_output = true;
        do_ioctl(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_IOCTL_REQBUFS,&rb,&mut out,log)?;
        output_count = virtio_media::read_u32(&out,0);
        if output_count < 2 || output_count > output_limit || output_count as usize > crate::encoder_state::MAX_ENCODER_OUTPUTS {
            return Err(virtio_media::Error::Errno(12));
        }
        let input_total=(input_count as usize).checked_mul(input_size as usize).ok_or(virtio_media::Error::Errno(12))?;
        let output_total=(output_count as usize).checked_mul(output_size as usize).ok_or(virtio_media::Error::Errno(12))?;
        if input_total.checked_add(output_total).filter(|&n|n<=pool_budget).is_none(){
            return Err(virtio_media::Error::Errno(12));
        }
        for (kind,count,ty,need) in [
            (0u8,input_count,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,input_size),
            (1u8,output_count,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,output_size),
        ] {
            for index in 0..count {
                let mut qb = [0u8; virtio_media::V4L2_BUFFER_SIZE];
                build_buffer(&mut qb,index,ty,virtio_media::V4L2_MEMORY_MMAP,0,0,1);
                do_ioctl(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_IOCTL_QUERYBUF,&qb,&mut out,log)?;
                let plane=virtio_media::V4L2_BUFFER_SIZE;
                let length=virtio_media::read_u32(&out,plane+virtio_media::V4L2_PLANE_LENGTH);
                let mem_offset=virtio_media::read_u32(&out,plane+virtio_media::V4L2_PLANE_OFFSET);
                if length<need { return Err(virtio_media::Error::ShortFrame(length as usize,need as usize)); }
                let (driver_addr,mmap_len)=do_mmap(mmio,q0,req_base,resp,host_id,mem_offset,log)?;
                let end=driver_addr.checked_add(mmap_len).ok_or(virtio_media::Error::Errno(12))?;
                if end>pool_size as u64||mmap_len<length as u64 {
                    let _=do_munmap(mmio,q0,req_base,resp,driver_addr,log);
                    return Err(virtio_media::Error::PoolTooSmall(end,pool_size as u64));
                }
                if ranges.insert(index,kind,driver_addr,driver_addr,mmap_len,mem_offset,length).is_err(){
                    let _=do_munmap(mmio,q0,req_base,resp,driver_addr,log);
                    return Err(virtio_media::Error::PoolTooSmall(end,pool_size as u64));
                }
            }
        }
        for index in 0..output_count {
            let range=ranges.range(index,1).ok_or(virtio_media::Error::DeviceStatus(0))?;
            qbuf(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                index,range.mem_offset,range.buffer_len,0,0,log)?;
        }
        let queues=crate::encoder_state::EncoderQueueConfig{
            input_type:virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
            output_type:virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
            input_count,output_count,input_sizeimage:input_size,output_sizeimage:output_size,streamon_mask:2,
        };
        state.configure_queues(queues,&ranges).map_err(|_|virtio_media::Error::DeviceStatus(0))?;
        streamon(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,"encoder CAPTURE",log)?;
        streamon_mask|=2;
        Ok(())
    })();
    if let Err(error)=result {
        if streamon_mask&1!=0 { streamoff(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,"encoder OUTPUT",log); }
        if streamon_mask&2!=0 { streamoff(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,"encoder CAPTURE",log); }
        while let Some(range)=ranges.pop_any() { let _=do_munmap(mmio,q0,req_base,resp,range.driver_addr,log); }
        if allocated_output { free_queue(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,"encoder CAPTURE",log); }
        if allocated_input { free_queue(mmio,q0,req_base,resp,host_id,virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,"encoder OUTPUT",log); }
        state.abort_configure();
        return Err(error);
    }
    Ok(())
}

/// same session, so an un-rolled-back half-configure used to be paid for on
/// every later frame and, through the unreleased `REQBUFS` allocation, by every
/// later codec in the same boot.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn configure_and_send(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    pool_va: *mut u8,
    pool_size: usize,
    pool_budget: usize,
    session_id: u32,
    codec: u32,
    width: u32,
    height: u32,
    bitstream: &[u8],
    drain: bool,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> Result<vmedia_abi::VM_SEND_OUT, virtio_media::Error> {
    match configure_and_send_inner(
        mmio, q0, req_base, resp, pool_va, pool_size, pool_budget, session_id, codec,
        width, height, bitstream, drain, cfg, log,
    ) {
        Ok(v) => Ok(v),
        Err(e) => {
            if cfg.stop_failed { return Err(e); } // AU accepted: preserve state, never rollback/replay.
            vlog(
                log,
                format_args!(
                    "SEND: configure failed ({}) -> rollback (STREAMOFF + MUNMAP + REQBUFS(0)) before returning",
                    e.text()
                ),
            );
            let _ = rollback_configure(mmio, q0, req_base, resp, session_id, cfg, log);
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn configure_and_send_inner(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    pool_va: *mut u8,
    pool_size: usize,
    pool_budget: usize,
    session_id: u32,
    codec: u32,
    width: u32,
    height: u32,
    bitstream: &[u8],
    drain: bool,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> Result<vmedia_abi::VM_SEND_OUT, virtio_media::Error> {
    let (coded_format, coded_name) = codec_fourcc(codec);
    let _ = coded_name;
    if width < 16 || height < 16 || width > 4096 || height > 4096 || (width & 1) != 0 || (height & 1) != 0 {
        vlog(log, format_args!("SEND: bad geometry {}x{}", width, height));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    if bitstream.is_empty() || bitstream.len() > u32::MAX as usize {
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    // 1.0.0.12: the caller hands us the live cfg (already emptied) and we fill it
    // in as we go, instead of building a local one and throwing it away on an
    // error.  Anything mapped before a failure therefore stays reachable: CLOSE,
    // the next OPEN and the pool sweep all release it.  The old local cfg is what
    // made a failed configure leak every pool range it had already mapped.
    cfg.width = width;
    cfg.height = height;

    // ---- formats ---------------------------------------------------------
    let mut fmt = [0u8; virtio_media::V4L2_FORMAT_SIZE];
    let mut out = [0u8; 256];
    virtio_media::write_u32(
        &mut fmt,
        virtio_media::V4L2_FORMAT_TYPE,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
    );
    do_ioctl(
        mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_G_FMT, &fmt, &mut out, log,
    )?;
    log_fmt("G_FMT OUTPUT", &out, log);

    build_fmt(
        &mut fmt,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        width,
        height,
        coded_format,
        0,
        0,
    );
    do_ioctl(
        mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_S_FMT, &fmt, &mut out, log,
    )?;
    log_fmt("S_FMT OUTPUT", &out, log);
    {
        let accepted = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_PIXELFORMAT);
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "S_FMT OUTPUT asked fourcc 0x{:08X} ({}), device accepted 0x{:08X} ({})",
            coded_format,
            coded_name,
            accepted,
            fourcc_name(accepted)
        );
        vlog(log, format_args!("{}", line.as_str()));
        if accepted != coded_format {
            // A device that answers a different fourcc is a different host
            // decoder: the bytes of this session would be misparsed.  Fail the
            // configure instead of decoding nothing until the GET_FRAME timeout.
            let mut err = virtio_media::LineBuf::new();
            let _ = write!(
                err,
                "S_FMT OUTPUT: device did not accept the {} codec (asked 0x{:08X}, got 0x{:08X})",
                coded_name, coded_format, accepted
            );
            vlog(log, format_args!("{}", err.as_str()));
            return Err(virtio_media::Error::DeviceStatus(0));
        }
    }
    let output_sizeimage = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_SIZEIMAGE);
    if output_sizeimage == 0 {
        vlog(log, format_args!("S_FMT OUTPUT returned sizeimage=0"));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    if bitstream.len() > output_sizeimage as usize {
        vlog(
            log,
            format_args!(
                "SEND: bitstream {} bytes > output sizeimage {}",
                bitstream.len(), output_sizeimage
            ),
        );
        return Err(virtio_media::Error::BitstreamTooLarge(bitstream.len(), output_sizeimage));
    }

    // ---- CAPTURE format: NV12, or P010 for a HEVC Main10 session ----------
    //
    // HEVC-MAIN10 (1.0.0.21): a Main10 session wants a 10-bit capture queue, so
    // it asks S_FMT CAPTURE for V4L2_PIX_FMT_P010 first and only accepts an
    // answer that *is* P010.  Everything else falls back to the pre-1.0.0.21
    // NV12 request, and the reason is logged, because the two outcomes are not
    // equivalent: P010 carries 10 bits per sample, NV12 carries 8 and the picture
    // loses the two low bits.  A fallback must never fail the session -- the host
    // is allowed to offer NV12 only, which is exactly what the crosvm
    // virtio-media decoder behind the tablet does today ("CAPTURE is always
    // NV12", host-ref video_decoder.rs:1666/1714).  Only a refused NV12 request
    // is fatal, as it was before.
    //
    // sizeimage/stride follow the fourcc that was *accepted*: a P010 row is
    // width * 2 bytes, so the whole geometry (tight frame, row copy) doubles.
    let requested_depth = codec_bit_depth(codec);
    let requested_p010 = requested_depth >= 10;
    let mut capture_fourcc = virtio_media::V4L2_PIX_FMT_NV12;
    let candidates: &[u32] = if requested_p010 {
        &[virtio_media::V4L2_PIX_FMT_P010, virtio_media::V4L2_PIX_FMT_NV12]
    } else {
        &[virtio_media::V4L2_PIX_FMT_NV12]
    };
    for (index, want) in candidates.iter().enumerate() {
        let last = index + 1 == candidates.len();
        build_fmt(
            &mut fmt,
            virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
            width,
            height,
            *want,
            0,
            width.saturating_mul(capture_bytes_per_sample(*want)),
        );
        match do_ioctl(
            mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_S_FMT, &fmt, &mut out, log,
        ) {
            Ok(_) => {
                log_fmt(
                    if *want == virtio_media::V4L2_PIX_FMT_P010 {
                        "S_FMT CAPTURE (P010 request)"
                    } else {
                        "S_FMT CAPTURE"
                    },
                    &out,
                    log,
                );
                let accepted = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_PIXELFORMAT);
                if accepted == *want {
                    capture_fourcc = accepted;
                    break;
                }
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "S_FMT CAPTURE: asked 0x{:08X} ({}), device answered 0x{:08X} ({}); {}",
                    *want,
                    capture_fourcc_name(*want),
                    accepted,
                    capture_fourcc_name(accepted),
                    if last {
                        "no 8-bit NV12 queue either -> failing the configure"
                    } else {
                        "falling back to V4L2_PIX_FMT_NV12 (8-bit capture)"
                    }
                );
                vlog(log, format_args!("{}", line.as_str()));
                if last {
                    return Err(virtio_media::Error::DeviceStatus(0));
                }
            }
            Err(e) => {
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "S_FMT CAPTURE: {} request (0x{:08X}) refused: {}; {}",
                    capture_fourcc_name(*want),
                    *want,
                    e.text(),
                    if last {
                        "the CAPTURE queue cannot be configured -> failing the configure"
                    } else {
                        "falling back to V4L2_PIX_FMT_NV12 (8-bit capture)"
                    }
                );
                vlog(log, format_args!("{}", line.as_str()));
                if last {
                    return Err(virtio_media::Error::DeviceStatus(0));
                }
            }
        }
    }
    if requested_p010 && capture_fourcc != virtio_media::V4L2_PIX_FMT_P010 {
        // One line that says what a Main10 session really got.  It is not an
        // error (the fallback is a supported outcome), but it is the number that
        // explains an 8-bit-looking picture on a 10-bit asset.
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "S_FMT CAPTURE: HEVC Main10 session on an 8-bit capture queue ({}): the host did not take P010, so the decoded picture is 8-bit and the UMD expands it into its P010 surface (b<<8) -- true 10-bit needs a host (virtio-media) that offers V4L2_PIX_FMT_P010",
            capture_fourcc_name(capture_fourcc)
        );
        vlog(log, format_args!("{}", line.as_str()));
    }
    let mut capture_sizeimage = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_SIZEIMAGE);
    let mut capture_stride = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_BYTESPERLINE);
    cfg.width = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_WIDTH);
    cfg.height = virtio_media::read_u32(&out, virtio_media::V4L2_FORMAT_HEIGHT);
    let negotiated_bps = capture_bytes_per_sample(capture_fourcc);
    let negotiated_row_bytes = cfg.width.saturating_mul(negotiated_bps);
    if capture_sizeimage == 0 {
        capture_sizeimage = negotiated_row_bytes * cfg.height * 3 / 2;
    }
    if capture_stride == 0 {
        capture_stride = negotiated_row_bytes;
    }
    cfg.capture_fourcc = capture_fourcc;
    cfg.capture_bit_depth = negotiated_bps * 8;
    cfg.capture_sizeimage = capture_sizeimage;
    cfg.capture_stride = capture_stride;
    cfg.output_sizeimage = output_sizeimage;
    vlog(
        log,
        format_args!(
            "S_FMT CAPTURE negotiated: {} ({}-bit, {} bytes/sample) {}x{} stride={} sizeimage={} (row {} B)",
            capture_fourcc_name(capture_fourcc),
            cfg.capture_bit_depth,
            negotiated_bps,
            cfg.width,
            cfg.height,
            capture_stride,
            capture_sizeimage,
            negotiated_row_bytes
        ),
    );

    // ---- capture queue (MMAP, from the media_host pool) ------------------
    //
    // 1.0.0.20 / E173: ask for what the pool can actually hold.
    //
    // The `media_host` pool is one budget shared by every session (64 MiB on the
    // current VMM) and a frame is allocated at the height the UMD asked for:
    // H.264/VP9 come out 1920x1088 (3,133,440 B) but AV1/HEVC are 1920x1152
    // (3,317,760 B).  Twenty of the latter plus the two OUTPUT buffers is
    // 69,672,960 B -- 2.4 MiB over the pool -- so `REQBUFS(20)` answered ENOMEM,
    // and so did every retry (16/12/8/6/4/2): the request that failed had already
    // left the host's queue holding the buffers it could allocate, and nothing
    // gave them back.  That is what poisoned the device for the rest of the boot
    // (E172: AV1 -> 616 x err=1450, then H.264 720p -> 574 x err=1450).
    //
    // So: ask = min(20, pool/sizeimage - 2), never below 2.  The two reserved
    // frames cover the OUTPUT queue (2 x ~sizeimage/2); at 1920x1152 this is
    // 64 MiB / 3,317,760 = 20 -> 18, i.e. 59.7 MiB + 3.2 MiB of OUTPUT.
    // Every refusal below is followed by `REQBUFS(0)` on the same queue, so the
    // attempts cannot accumulate; a failure that survives all of them calls
    // `rollback_configure` from the `configure_and_send` wrapper.
    let frame_capacity = if capture_sizeimage == 0 {
        CAPTURE_BUFS
    } else {
        core::cmp::min(CAPTURE_BUFS, (pool_budget as u64 / capture_sizeimage as u64) as u32)
    };
    let budget_ask = core::cmp::max(MIN_CAPTURE_BUFS, frame_capacity.saturating_sub(OUTPUT_BUFS));
    vlog(
        log,
        format_args!(
            "REQBUFS CAPTURE budget: pool={} B ({} MiB), this session's share={} B, sizeimage={} B -> {} frame(s) fit, {} reserved for OUTPUT -> ask={}",
            pool_size,
            pool_size >> 20,
            pool_budget,
            capture_sizeimage,
            frame_capacity,
            OUTPUT_BUFS,
            budget_ask
        ),
    );
    let mut rb = [0u8; virtio_media::V4L2_REQBUFS_SIZE];
    let mut capture_count = 0u32;
    let mut tried: u32 = 0;
    for ask in [budget_ask, 16, 12, 8, 6, 4, 2] {
        if ask == 0 || ask > budget_ask {
            continue;
        }
        virtio_media::write_u32(&mut rb, 0, ask);
        virtio_media::write_u32(&mut rb, 4, virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE);
        virtio_media::write_u32(&mut rb, 8, virtio_media::V4L2_MEMORY_MMAP);
        match do_ioctl(
            mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_REQBUFS, &rb, &mut out, log,
        ) {
            Ok(_) => {
                let granted = virtio_media::read_u32(&out, 0);
                vlog(
                    log,
                    format_args!(
                        "REQBUFS CAPTURE: asked {} granted {} (sizeimage={} stride={} pool={} B, budget ask {})",
                        ask, granted, capture_sizeimage, capture_stride, pool_size, budget_ask
                    ),
                );
                if granted > 0 && granted as usize <= MAX_CAPTURE_BUFS {
                    capture_count = granted;
                    break;
                }
                // A zero grant is the same poisoned-queue case as an errno: free
                // whatever the host allocated anyway before trying smaller.
                free_queue(
                    mmio,
                    q0,
                    req_base,
                    resp,
                    session_id,
                    virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                    "CAPTURE",
                    log,
                );
            }
            Err(e) => {
                vlog(
                    log,
                    format_args!("REQBUFS CAPTURE: asked {} refused: {}", ask, e.text()),
                );
                // E173: the refused request may have left the host queue holding
                // the buffers it managed to allocate before the pool ran out.
                // Give them back before the next (smaller) attempt.
                free_queue(
                    mmio,
                    q0,
                    req_base,
                    resp,
                    session_id,
                    virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                    "CAPTURE",
                    log,
                );
            }
        }
        tried = ask;
    }
    if capture_count == 0 {
        vlog(
            log,
            format_args!(
                "REQBUFS CAPTURE: no ask fitted (last {}); each refusal freed its queue, rolling this configure back -> ENOMEM",
                tried
            ),
        );
        return Err(virtio_media::Error::Errno(12));
    }
    cfg.capture_count = capture_count;

    for i in 0..capture_count {
        let mut qb = [0u8; virtio_media::V4L2_BUFFER_SIZE];
        build_buffer(
            &mut qb,
            i,
            virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
            virtio_media::V4L2_MEMORY_MMAP,
            0,
            0,
            1,
        );
        do_ioctl(
            mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_QUERYBUF, &qb, &mut out, log,
        )?;
        let plane = virtio_media::V4L2_BUFFER_SIZE;
        let length = virtio_media::read_u32(&out, plane + virtio_media::V4L2_PLANE_LENGTH);
        let offset = virtio_media::read_u32(&out, plane + virtio_media::V4L2_PLANE_OFFSET);
        let (addr, mlen) = do_mmap(mmio, q0, req_base, resp, session_id, offset, log)?;
        if addr > pool_size as u64 || mlen > pool_size as u64 || addr + mlen > pool_size as u64 {
            vlog(
                log,
                format_args!(
                    "capture[{}]: mmap offset 0x{:X} len 0x{:X} outside pool 0x{:X}",
                    i, addr, mlen, pool_size
                ),
            );
            return Err(virtio_media::Error::PoolTooSmall(addr + mlen, pool_size as u64));
        }
        cfg.cap_va[i as usize] = pool_va.add(addr as usize);
        cfg.cap_len[i as usize] = length;
        cfg.cap_off[i as usize] = offset;
        cfg.cap_addr[i as usize] = addr;
        cfg.cap_mapped |= 1u32 << i;
        if i == 0 || i + 1 == capture_count {
            vlog(
                log,
                format_args!(
                    "capture[{}]: size={} mem_offset=0x{:X} mmap_addr=0x{:X} len=0x{:X} va=0x{:X}",
                    i, length, offset, addr, mlen, cfg.cap_va[i as usize] as usize
                ),
            );
        }
    }

    // ---- output queue ----------------------------------------------------
    let mut output_count = 0u32;
    for ask in [OUTPUT_BUFS, 1] {
        virtio_media::write_u32(&mut rb, 0, ask);
        virtio_media::write_u32(&mut rb, 4, virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE);
        virtio_media::write_u32(&mut rb, 8, virtio_media::V4L2_MEMORY_MMAP);
        match do_ioctl(
            mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_REQBUFS, &rb, &mut out, log,
        ) {
            Ok(_) => {
                let granted = virtio_media::read_u32(&out, 0);
                vlog(
                    log,
                    format_args!("REQBUFS OUTPUT: asked {} granted {} (sizeimage={})", ask, granted, output_sizeimage),
                );
                if granted > 0 && granted as usize <= MAX_OUTPUT_BUFS {
                    output_count = granted;
                    break;
                }
                free_queue(
                    mmio,
                    q0,
                    req_base,
                    resp,
                    session_id,
                    virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                    "OUTPUT",
                    log,
                );
            }
            Err(e) => {
                vlog(log, format_args!("REQBUFS OUTPUT: asked {} refused: {}", ask, e.text()));
                // E173: never leave a half-allocated OUTPUT queue behind.
                free_queue(
                    mmio,
                    q0,
                    req_base,
                    resp,
                    session_id,
                    virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
                    "OUTPUT",
                    log,
                );
            }
        }
    }
    if output_count == 0 {
        vlog(log, format_args!("REQBUFS OUTPUT: no bitstream buffer at all -> ENOMEM (rolling back)"));
        return Err(virtio_media::Error::Errno(12));
    }
    cfg.output_count = output_count;

    for i in 0..output_count {
        let mut qb = [0u8; virtio_media::V4L2_BUFFER_SIZE];
        build_buffer(
            &mut qb,
            i,
            virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
            virtio_media::V4L2_MEMORY_MMAP,
            0,
            0,
            1,
        );
        do_ioctl(
            mmio, q0, req_base, resp, session_id, virtio_media::V4L2_IOCTL_QUERYBUF, &qb, &mut out, log,
        )?;
        let plane = virtio_media::V4L2_BUFFER_SIZE;
        let length = virtio_media::read_u32(&out, plane + virtio_media::V4L2_PLANE_LENGTH);
        let offset = virtio_media::read_u32(&out, plane + virtio_media::V4L2_PLANE_OFFSET);
        let (addr, mlen) = do_mmap(mmio, q0, req_base, resp, session_id, offset, log)?;
        if addr > pool_size as u64 || mlen > pool_size as u64 || addr + mlen > pool_size as u64 {
            return Err(virtio_media::Error::PoolTooSmall(addr + mlen, pool_size as u64));
        }
        cfg.out_va[i as usize] = pool_va.add(addr as usize);
        cfg.out_len[i as usize] = length;
        cfg.out_off[i as usize] = offset;
        cfg.out_addr[i as usize] = addr;
        cfg.out_mapped |= 1u32 << i;
        vlog(
            log,
            format_args!(
                "output[{}]: size={} mem_offset=0x{:X} mmap_addr=0x{:X} len=0x{:X}",
                i, length, offset, addr, mlen
            ),
        );
    }

    // ---- fill output[0] with the caller's access unit --------------------
    // 1.0.0.12: do NOT zero the tail of the OUTPUT buffer.  The host reads
    // exactly `bytesused` bytes of the access unit (`lend_input` uses the plane's
    // bytesused), and this buffer lives in the media_host pool, which is mapped
    // PAGE_NOCACHE: zeroing the remaining 1.5 MiB (1080p) cost more than the
    // whole host hand-over.  E148.
    let bitstream_len = bitstream.len();
    ptr::copy_nonoverlapping(bitstream.as_ptr(), cfg.out_va[0], bitstream_len);
    // 1.0.0.23 CACHED-POOL: the pool is cached now, so the bytes we just wrote
    // may still be dirty in this CPU's cache.  Clean them back to memory before
    // the host is told to read them (the S_FMT/STREAMON hand-over below).
    if POOL_CACHED.load(Ordering::SeqCst) {
        cache_clean_invalidate_range(cfg.out_va[0], bitstream_len);
    }
    vlog(
        log,
        format_args!("bitstream: {} bytes into output[0] (buffer {} bytes)", bitstream_len, cfg.out_len[0]),
    );

    // ---- SUBSCRIBE_EVENT(SOURCE_CHANGE) ----------------------------------
    let mut sub = [0u8; 32];
    virtio_media::write_u32(&mut sub, 0, virtio_media::V4L2_EVENT_SOURCE_CHANGE);
    virtio_media::write_u32(&mut sub, 4, 0);
    virtio_media::write_u32(&mut sub, 8, 0);
    let mut sub_out = [0u8; 8];
    do_ioctl(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_IOCTL_SUBSCRIBE_EVENT,
        &sub,
        &mut sub_out,
        log,
    )?;
    vlog(log, format_args!("SUBSCRIBE_EVENT SOURCE_CHANGE ok"));
    virtio_media::write_u32(&mut sub, 0, 2); // V4L2_EVENT_EOS
    do_ioctl(mmio, q0, req_base, resp, session_id,
        virtio_media::V4L2_IOCTL_SUBSCRIBE_EVENT, &sub, &mut sub_out, log)?;
    vlog(log, format_args!("SUBSCRIBE_EVENT EOS ok"));

    // ---- QBUF all capture buffers, then output[0] ------------------------
    for i in 0..capture_count {
        qbuf(
            mmio,
            q0,
            req_base,
            resp,
            session_id,
            virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
            i,
            cfg.cap_off[i as usize],
            cfg.cap_len[i as usize],
            0,
            0,
            log,
        )?;
    }
    qbuf(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        0,
        cfg.out_off[0],
        cfg.out_len[0],
        bitstream_len as u32,
        cfg.send_tag,
        log,
    )?;
    vlog(
        log,
        format_args!("QBUF: {} capture buffers + output[0] ({} bytes)", capture_count, bitstream_len),
    );

    // Device prepare already posted event buffers once for this q1 lifetime.
    // Session configure/FLUSH/reopen preserves q1 and its in-flight descriptors.

    // ---- STREAMON capture, then output (starts the codec) ----------------
    streamon(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
        "CAPTURE",
        log,
    )?;
    streamon(
        mmio,
        q0,
        req_base,
        resp,
        session_id,
        virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,
        "OUTPUT",
        log,
    )?;


    // P3/1.0.0.10: the session is now streaming and reusable.  OUTPUT[0] is the
    // access unit queued above, so only the remaining OUTPUT buffers count as
    // free; every CAPTURE buffer was queued just before STREAMON.
    cfg.configured = true;
    cfg.cap_queued = mask_bits(capture_count);
    cfg.out_free = mask_bits(output_count) & !1u32;
    cfg.aus_queued = 1;
    vlog(
        log,
        format_args!(
            "session configured: capture {} queued (mask 0x{:X}), output free mask 0x{:X} -- later SENDs reuse this session",
            capture_count, cfg.cap_queued, cfg.out_free
        ),
    );

    if drain {
        if let Err(e) = decoder_stop(mmio, q0, req_base, resp, session_id, log) {
            cfg.stop_failed = true;
            vlog(log, format_args!("SEND PARTIAL ACCEPTED: first AU queued; STOP failed; do not replay AU; FLUSH/CLOSE required"));
            return Err(e);
        }
    }

    let result = vmedia_abi::VM_SEND_OUT {
        Width: cfg.width,
        Height: cfg.height,
        OutputSizeImage: cfg.output_sizeimage,
        CaptureSizeImage: cfg.capture_sizeimage,
        CaptureStride: cfg.capture_stride,
        CaptureCount: cfg.capture_count,
        Reserved0: 0,
        Reserved1: 0,
    };
    Ok(result)
}

/// P3-2 / 1.0.0.11: flush the host session -- close it (which MUNMAPs the pool
/// ranges first) and open a fresh one, so the next [`configure_and_send`] starts
/// from a clean decoder with no references, no queued AUs and no pending frames.
///
/// This is what makes seek / loop / pause-resume work: the player jumps to a new
/// point, the UMD sees an IDR (or a new SPS/PPS) and calls `VM_IOCTL_FLUSH`, and
/// the access unit that follows is decoded by a decoder that has never seen the
/// old stream.  A refused CLOSE is not fatal -- the guest drops its state and
/// the fresh session is still opened.
pub(crate) unsafe fn flush_session(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    session_id: u32,
    cfg: &mut SessionConfig,
    log: &mut dyn virtio_media::Log,
) -> Result<u32, virtio_media::Error> {
    match close_session(mmio, q0, req_base, resp, session_id, cfg, 4000, log) {
        Ok(()) => vlog(log, format_args!("FLUSH: session {} closed", session_id)),
        Err(e) => vlog(
            log,
            format_args!(
                "FLUSH: device refused CLOSE of session {} ({}) -- opening the fresh session anyway",
                session_id,
                e.text()
            ),
        ),
    }
    let new_id = open_session(mmio, q0, req_base, resp, log)?;
    vlog(log, format_args!("FLUSH: fresh host session {} open (was {})", new_id, session_id));
    Ok(new_id)
}

/// `V4L2_DEC_CMD_STOP` -- ask the decoder to drain.  Used only for an explicit
/// `drain` SEND (the P2-2i probe's last AU); a streaming session never stops
/// the codec between frames.
// Author UAPI: cmd4 + flags4 + union(raw[16])64 = 72, not 16.
/// V4L2 encoder command: cmd4 + flags4 + raw[8]32. STOP acceptance
/// is synchronous; completion is reported later by a CAPTURE buffer with LAST.
pub(crate) unsafe fn encoder_stop(
    mmio:&mut Kmmio,q0:&mut virtio_media::Queue,
    req:&virtio_media::Buf,resp:&virtio_media::Buf,
    host_id:u32,log:&mut dyn virtio_media::Log,
)->Result<(),virtio_media::Error>{
    let mut command=[0u8;40];
    virtio_media::write_u32(&mut command,0,1);
    let mut out=[0u8;40];
    let n=do_ioctl(mmio,q0,req,resp,host_id,virtio_media::V4L2_IOCTL_ENCODER_CMD,&command,&mut out,log)?;
    if n<40||virtio_media::read_u32(&out,0)!=1||virtio_media::read_u32(&out,4)!=0{
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    Ok(())
}

const DECODER_CMD_SIZE: usize = 72;
fn decoder_command(cmd: u32) -> [u8; DECODER_CMD_SIZE] {
    let mut bytes = [0u8; DECODER_CMD_SIZE];
    virtio_media::write_u32(&mut bytes, 0, cmd);
    bytes
}
fn decoder_response_valid(n: usize, bytes: &[u8], cmd: u32) -> bool {
    n >= DECODER_CMD_SIZE && bytes.len() >= DECODER_CMD_SIZE
        && virtio_media::read_u32(bytes, 0) == cmd
        && virtio_media::read_u32(bytes, 4) == 0
}
pub(crate) unsafe fn decoder_stop(
    mmio: &mut Kmmio, q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf, resp: &virtio_media::Buf,
    session_id: u32, log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let dec = decoder_command(virtio_media::V4L2_DEC_CMD_STOP);
    let mut out = [0u8; DECODER_CMD_SIZE];
    let n = do_ioctl(mmio, q0, req_base, resp, session_id,
        virtio_media::V4L2_IOCTL_DECODER_CMD, &dec, &mut out, log)?;
    if !decoder_response_valid(n, &out, virtio_media::V4L2_DEC_CMD_STOP) {
        vlog(log, format_args!("DECODER_CMD STOP INVALID RESPONSE: session={} payload={} used={} expected>=80", session_id, n, n + 8));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    vlog(log, format_args!("DECODER_CMD STOP ACCEPTED: session={} payload={} used={} cmd=1 flags=0; awaiting LAST/EOS", session_id, n, n + 8));
    Ok(())
}

/// Queue one more access unit on an already configured session (P3/1.0.0.10).
///
/// This is the multi-AU path: the formats, the REQBUFS grants, the MMAPs, the
/// event subscription and both STREAMONs happened on the first SEND
/// ([`configure_and_send`]); here the AU is copied into a free OUTPUT buffer and
/// that buffer is queued.  The device hands the buffer back with
/// `DQBUF(OUTPUT)` once the codec has consumed it (`InputBufferDone` in the
/// host's video_decoder.rs), which is what sets `out_free` again.
///
/// If both OUTPUT buffers are still lent (the DQBUF arrived after the previous
/// GET_FRAME returned), pump the event queue until one comes back; a decoded
/// frame met on the way is stashed in `pending` for the next GET_FRAME so no
/// frame is lost.  That is the whole reason the driver needs no extra buffers:
/// the 64 MiB media_host pool must still fit the two 720p sessions PotPlayer
/// creates.
pub(crate) unsafe fn submit_access_unit(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    fan: &mut Fanout,
    cfg: &mut SessionConfig,
    pending: &mut PendingFrames,
    bitstream: &[u8],
    drain: bool,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    if !cfg.configured {
        vlog(log, format_args!("SEND: session is not configured"));
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    if bitstream.is_empty() || bitstream.len() > u32::MAX as usize {
        return Err(virtio_media::Error::DeviceStatus(0));
    }
    if bitstream.len() > cfg.output_sizeimage as usize {
        vlog(
            log,
            format_args!(
                "SEND: access unit {} bytes > OUTPUT sizeimage {} (cannot grow it while streaming)",
                bitstream.len(), cfg.output_sizeimage
            ),
        );
        return Err(virtio_media::Error::BitstreamTooLarge(bitstream.len(), cfg.output_sizeimage));
    }

    let mut spins = 0u32;
    let mut waited = false;
    let t_wait0 = qpc_now();
    let index = loop {
        let free = cfg.out_free & mask_bits(cfg.output_count);
        if free != 0 {
            break free.trailing_zeros();
        }
        if !waited {
            waited = true;
            vlog(log, format_args!("SEND: both OUTPUT buffers lent, waiting for DQBUF(OUTPUT)"));
        }
        match pump_event(mmio, q0, req_base, resp, cfg, fan, log) {
            Pump::Frame(index, used) => pending.push(index, used),
            Pump::Error(errno) => return Err(virtio_media::Error::Errno(errno)),
            Pump::Handled => {}
            Pump::Idle => {
                spins += 1;
                // 2 s, same order as the UMD's 1 s GET_FRAME timeout.
                if spins >= 4000 {
                    vlog(log, format_args!("SEND: no free OUTPUT buffer after {} spins", spins));
                    return Err(virtio_media::Error::DeviceStatus(0));
                }
                irq::wait(mmio.wdf_device);
            }
        }
    };

    let i = index as usize;
    let t_buf = qpc_now();
    // 1.0.0.12: no tail zeroing -- the host honours `bytesused` (`lend_input`),
    // and clearing the remaining ~1.5 MiB of a PAGE_NOCACHE pool buffer every
    // access unit was pure cost.  E148.
    ptr::copy_nonoverlapping(bitstream.as_ptr(), cfg.out_va[i], bitstream.len());
    // 1.0.0.23 CACHED-POOL: clean the access unit back to memory before the
    // QBUF below hands the buffer to the host (see the file's cache comment).
    if POOL_CACHED.load(Ordering::SeqCst) {
        cache_clean_invalidate_range(cfg.out_va[i], bitstream.len());
    }
    let t_copy = qpc_now();
    qbuf_async(mmio, q0, fan.own_host, cfg, index, bitstream.len() as u32, fan.owner, log)?;
    cfg.out_free &= !(1u32 << index);
    cfg.aus_queued = cfg.aus_queued.saturating_add(1);
    if cfg.aus_queued <= 3 || cfg.aus_queued % 30 == 0 {
        let t_end = qpc_now();
        vlog(
            log,
            format_args!(
                "SEND q={} in-flight={} AU#{} {} bytes -> output[{}] queued async (free mask 0x{:X})",
                q0.async_inflight, q0.async_inflight, cfg.aus_queued, bitstream.len(), index, cfg.out_free
            ),
        );
        vlog(
            log,
            format_args!(
                "SEND timing: wait_for_buffer={:.2} ms au_copy={:.2} ms handover={:.2} ms",
                qpc_ms_between(t_wait0, t_buf),
                qpc_ms_between(t_buf, t_copy),
                qpc_ms_between(t_copy, t_end)
            ),
        );
    }
    if drain {
        if let Err(e) = decoder_stop(mmio, q0, req_base, resp, fan.own_host, log) {
            cfg.stop_failed = true;
            vlog(log, format_args!("SEND PARTIAL ACCEPTED: AU queued; STOP failed; do not replay AU; FLUSH/CLOSE required"));
            return Err(e);
        }
    }
    Ok(())
}

/// One event from the eventq, turned into buffer bookkeeping.
enum Pump {
    /// No event was pending.
    Idle,
    /// An event was consumed; nothing to hand to GET_FRAME.
    Handled,
    /// `DQBUF(CAPTURE)` -- (capture index, bytesused).
    Frame(u32, u32),
    /// `VIRTIO_MEDIA_EVENT_ERROR` -- errno.
    Error(i32),
}

/// One eventq entry, parsed but not yet applied.
///
/// PER-SESSION-LIVESTATE (1.0.0.25): parsing and applying are separate so the
/// same note can be applied either to the session whose IOCTL is running (the
/// pre-1.0.0.25 path) or to the **other** session of the function (routed, see
/// [`Fanout`]) without writing the buffer bookkeeping twice.
#[derive(Clone, Copy)]
enum Note {
    /// `DQBUF(CAPTURE)` -- (index, bytesused)
    Capture(u32, u32, u64, u32),
    /// `DQBUF(OUTPUT)` -- (index, bytesused)
    Output(u32, u32),
    /// `EVENT` -- (`type`, `changes`)
    Event(u32, u32),
    /// `VIRTIO_MEDIA_EVENT_ERROR` -- errno
    Error(i32),
    /// A DQBUF of another buffer type, or an event kind this driver ignores.
    Ignored(u32),
}

// Linux reference: eventq_callback:403 / process_events:533 / repost:632 /
// avoid starving:641. PASSIVE command waiter adapts that independent progress
// contract without adding a DPC, worker, recursive command or SLOTS alias.
const EVENT_STASH_CAP: usize = 256;
#[derive(Clone, Copy, PartialEq, Eq)]
struct EventOwner { host: u32, token: u32 }
#[derive(Clone, Copy)]
struct SavedEvent { owner: EventOwner, note: Note }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EncoderNotice { InputDone{index:u32,bytesused:u32}, Packet{index:u32,bytesused:u32,timestamp:u64,timestamp_valid:bool,keyframe:bool,last:bool}, Error(i32), Other }
pub(crate) struct DeviceEvents {
    q1: virtio_media::Queue,
    evt: EventDma,
    stash: [Option<SavedEvent>; EVENT_STASH_CAP],
    head: usize,
    len: usize,
    owners: [EventOwner; VMEDIA_MAX_SESSIONS + 1],
    pub(crate) poisoned: bool,
    overflow: u64,
    harvested: u64,
    unknown: u64,
}
impl DeviceEvents {
    pub(crate) fn try_allocate() -> Option<Box<core::mem::MaybeUninit<Self>>> {
        let raw = unsafe { alloc::alloc::alloc(alloc::alloc::Layout::new::<Self>()) };
        if raw.is_null() { None } else { Some(unsafe { Box::from_raw(raw.cast()) }) }
    }
    /// No fallible work after owned evt transfer. FIFO initialized in final heap.
    pub(crate) unsafe fn initialize(mut raw: Box<core::mem::MaybeUninit<Self>>,
        q1: virtio_media::Queue, evt: EventDma) -> Box<Self> {
        let dst = raw.as_mut_ptr();
        let stash = ptr::addr_of_mut!((*dst).stash).cast::<Option<SavedEvent>>();
        for i in 0..EVENT_STASH_CAP { stash.add(i).write(None); }
        ptr::addr_of_mut!((*dst).head).write(0);
        ptr::addr_of_mut!((*dst).len).write(0);
        ptr::addr_of_mut!((*dst).owners).write([EventOwner { host: 0, token: 0 }; VMEDIA_MAX_SESSIONS + 1]);
        ptr::addr_of_mut!((*dst).poisoned).write(false);
        ptr::addr_of_mut!((*dst).overflow).write(0);
        ptr::addr_of_mut!((*dst).harvested).write(0);
        ptr::addr_of_mut!((*dst).unknown).write(0);
        ptr::addr_of_mut!((*dst).q1).write(q1);
        ptr::addr_of_mut!((*dst).evt).write(evt);
        raw.assume_init()
    }
    pub(crate) fn sync_owners(&mut self, slots: &[SessionSlot; VMEDIA_MAX_SESSIONS], encoder: crate::encoder_state::EncoderOwner) {
        for (dst, slot) in self.owners[..VMEDIA_MAX_SESSIONS].iter_mut().zip(slots) {
            *dst = EventOwner { host: if slot.open { slot.host_id } else { 0 },
                token: if slot.open { slot.token } else { 0 } };
        }
        self.owners[VMEDIA_MAX_SESSIONS] = EventOwner {
            host: if encoder.open { encoder.host_id } else { 0 },
            token: if encoder.open { encoder.token } else { 0 },
        };
    }
    fn owner_current(&self, owner: EventOwner) -> bool {
        owner.token != 0 && self.owners.contains(&owner)
    }
    fn pop(&mut self) -> Option<SavedEvent> {
        if self.len == 0 { return None; }
        let item = self.stash[self.head].take();
        self.head = (self.head + 1) % EVENT_STASH_CAP;
        self.len -= 1;
        item
    }
    pub(crate) fn pop_encoder_notice(&mut self,host:u32,token:u32)->Option<EncoderNotice>{
        let owner=EventOwner{host,token};
        let pos=(0..self.len).find(|&i|self.stash[(self.head+i)%EVENT_STASH_CAP].map(|e|e.owner==owner).unwrap_or(false))?;
        let item=self.stash[(self.head+pos)%EVENT_STASH_CAP].take()?;
        for i in pos..self.len-1{
            let from=(self.head+i+1)%EVENT_STASH_CAP;let to=(self.head+i)%EVENT_STASH_CAP;
            self.stash[to]=self.stash[from].take();
        }
        self.len-=1;
        match item.note{
            Note::Output(index,bytesused)=>Some(EncoderNotice::InputDone{index,bytesused}),
            Note::Capture(index,bytesused,timestamp,flags)=>Some(EncoderNotice::Packet{index,bytesused,timestamp,timestamp_valid:flags&0x0000_E000==virtio_media::V4L2_BUF_FLAG_TIMESTAMP_COPY,keyframe:flags&virtio_media::V4L2_BUF_FLAG_KEYFRAME!=0,last:flags&0x0010_0000!=0}),
            Note::Error(errno)=>Some(EncoderNotice::Error(errno)),
            _=>Some(EncoderNotice::Other),
        }
    }
    /// Pure transport progress: no apply_note, G_FMT, re-QBUF or other q0 use.
    /// Bound each pass so a hostile event stream cannot starve the q0 timeout.
    pub(crate) fn harvest(&mut self, mmio: &mut Kmmio) {
        for _ in 0..virtio_media::EVENT_COUNT {
            let Some((id, len)) = virtio_media::poll_event(&mut self.q1) else { break };
            if id >= virtio_media::EVENT_COUNT as u32 {
                self.poisoned = true; // full u32 validation, never truncate id
                continue;
            }
            let buf = self.evt.buf(id as u16);
            let mut bytes = [0u8; virtio_media::EVENT_CAP];
            let got = virtio_media::read_buf(&buf, &mut bytes);
            let n = (len as usize).min(got);
            if len as usize > virtio_media::EVENT_CAP || n < 8 {
                self.poisoned = true;
            } else {
                let host = virtio_media::read_u32(&bytes, 4);
                if let Some(owner) = self.owners.iter().find(|o| o.host == host && o.token != 0).copied() {
                    let note = parse_event(&bytes, n);
                    match note {
                        Note::Capture(index, used, tag, flags) if flags & 0x0010_0000 != 0 => {
                            vlog(&mut crate::IoLog, format_args!("DRAIN LAST OBSERVED: host={} token={} index={} bytesused={} tag={} flags=0x{:X}", owner.host, owner.token, index, used, tag, flags));
                        }
                        Note::Event(2, _) => {
                            vlog(&mut crate::IoLog, format_args!("DRAIN EOS OBSERVED: host={} token={} event=2", owner.host, owner.token));
                        }
                        _ => {}
                    }
                    if self.len == EVENT_STASH_CAP {
                        self.overflow = self.overflow.saturating_add(1);
                        self.poisoned = true;
                    } else if !self.poisoned {
                        self.stash[(self.head + self.len) % EVENT_STASH_CAP] = Some(SavedEvent { owner, note });
                        self.len += 1;
                    }
                } else {
                    self.unknown = self.unknown.saturating_add(1);
                }
            }
            // On fatal overflow discard only while explicitly poisoned; continue
            // returning DMA so an already-owned q0 command can terminate safely.
            virtio_media::post_event(mmio, &mut self.q1, &buf, id as u16);
            self.harvested = self.harvested.saturating_add(1);
        }
    }
}

/// Turn one event buffer into a [`Note`].  `n` is the used-ring length, which is
/// what the host wrote, not the buffer capacity.
fn capture_tag(event: &[u8]) -> u64 {
    let off = 8 + virtio_media::V4L2_BUFFER_TIMESTAMP;
    let sec = virtio_media::read_u64(event, off) as i64;
    let usec = virtio_media::read_u64(event, off + 8) as i64;
    let flags = virtio_media::read_u32(event, 8 + 12);
    if sec < 0 || usec < 0 || usec >= 1_000_000 || (flags & 0xE000) != 0x4000 { return 0; }
    (sec as u64).checked_mul(1_000_000).and_then(|v| v.checked_add(usec as u64)).filter(|v| *v <= i64::MAX as u64).unwrap_or(0)
}

fn parse_event(event: &[u8; virtio_media::EVENT_CAP], n: usize) -> Note {
    if n < 8 {
        return Note::Error(-22);
    }
    let kind = virtio_media::read_u32(event, 0);
    match kind {
        virtio_media::VIRTIO_MEDIA_EVENT_DQBUF => {
            if n < 8 + virtio_media::V4L2_BUFFER_SIZE { return Note::Error(-22); }
            let ty = virtio_media::read_u32(event, 8 + virtio_media::V4L2_BUFFER_TYPE);
            let index = virtio_media::read_u32(event, 8 + virtio_media::V4L2_BUFFER_INDEX);
            let used = virtio_media::read_u32(event, 8 + virtio_media::V4L2_BUFFER_BYTESUSED);
            let plane = 8 + virtio_media::V4L2_BUFFER_SIZE;
            if n < plane + virtio_media::V4L2_PLANE_SIZE { return Note::Error(-22); }
            let plane_used = virtio_media::read_u32(event, plane + virtio_media::V4L2_PLANE_BYTESUSED);
            if ty == virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE {
                Note::Capture(index, if plane_used != 0 { plane_used } else { used }, capture_tag(event), virtio_media::read_u32(event, 8 + 12))
            } else if ty == virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE {
                Note::Output(index, used)
            } else {
                Note::Ignored(ty)
            }
        }
        virtio_media::VIRTIO_MEDIA_EVENT_EVENT if n < 8 + virtio_media::V4L2_EVENT_SRC_CHANGES + 4 => Note::Error(-22),
        virtio_media::VIRTIO_MEDIA_EVENT_EVENT => Note::Event(
            virtio_media::read_u32(event, 8 + virtio_media::V4L2_EVENT_TYPE),
            virtio_media::read_u32(event, 8 + virtio_media::V4L2_EVENT_SRC_CHANGES),
        ),
        virtio_media::VIRTIO_MEDIA_EVENT_ERROR if n < 12 => Note::Error(-22),
        virtio_media::VIRTIO_MEDIA_EVENT_ERROR => {
            Note::Error(virtio_media::read_u32(event, 8) as i32)
        }
        other => Note::Ignored(other),
    }
}

/// Apply one [`Note`] to its owner's bookkeeping and say what the currently
/// running request may do with it.
///
/// `own` is true when the note belongs to the session whose IOCTL is running: the
/// useful outcomes (a decoded CAPTURE frame, an ERROR) go straight back to that
/// handler.  When it is false the note belongs to the **other** session of the
/// function: the frame is queued in *its* `PendingFrames`, the OUTPUT buffer is
/// freed in *its* `cfg`, and the error is latched in *its* `event_err`, so that
/// session finds it on its next IOCTL (`routed` counts the evidence).
#[allow(clippy::too_many_arguments)]
unsafe fn apply_note(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    host: u32,
    own: bool,
    cfg: &mut SessionConfig,
    frames: Option<&mut PendingFrames>,
    event_err: &mut i32,
    routed: &mut u32,
    note: Note,
    log: &mut dyn virtio_media::Log,
) -> Pump {
    match note {
        Note::Capture(index, used, tag, flags) => {
            if index >= cfg.capture_count || index as usize >= MAX_CAPTURE_BUFS { return Pump::Error(-22); }
            let bit = 1u32 << index;
            if (cfg.cap_queued & bit) == 0 { return Pump::Error(-22); }
            cfg.cap_queued &= !bit;
            cfg.cap_tag[index as usize] = tag;
            if flags & 0x0010_0000 != 0 && used == 0 {
                // Empty LAST is a drain marker, never pixels or a pending AU.
                cfg.cap_tag[index as usize] = 0;
                // Author session.cc:653-655 recycles empty LAST, never returns pixels.
                requeue_capture(mmio, q0, req_base, resp, host, cfg, index as usize, log);
                vlog(log, format_args!("DRAIN EMPTY LAST APPLIED: session={} index={} no pixel frame, recycled", host, index));
                return Pump::Handled;
            }
            if cfg.dqb_cap_logged < 3 {
                cfg.dqb_cap_logged += 1;
                vlog(
                    log,
                    format_args!(
                        "DQBUF CAPTURE: session {} index={} bytesused={} ({})",
                        host,
                        index,
                        used,
                        if own { "ours" } else { "routed to its owner" }
                    ),
                );
            }
            if own {
                return Pump::Frame(index, used);
            }
            if let Some(frames) = frames {
                if frames.len as usize >= MAX_PENDING_FRAMES {
                    *event_err = -28;
                    requeue_capture(mmio, q0, req_base, resp, host, cfg, index as usize, log);
                    vlog(log, format_args!("route: session {} capture frame {} queue full -> latched ENOSPC, capture requeued", host, index));
                    return Pump::Handled;
                } else {
                    frames.push(index, used);
                }
            }
            *routed = routed.saturating_add(1);
            Pump::Handled
        }
        Note::Output(index, used) => {
            if cfg.dqb_out_logged < 3 {
                cfg.dqb_out_logged += 1;
                vlog(
                    log,
                    format_args!(
                        "DQBUF OUTPUT: session {} index={} bytesused={} (buffer free again{})",
                        host,
                        index,
                        used,
                        if own { "" } else { ", routed to its owner" }
                    ),
                );
            }
            cfg.out_free |= 1u32 << index.min(31);
            if !own {
                *routed = routed.saturating_add(1);
            }
            Pump::Handled
        }
        Note::Event(ev_type, changes) => {
            vlog(
                log,
                format_args!(
                    "EVENT: session {} type={} (SOURCE_CHANGE={}) changes=0x{:X}{}",
                    host,
                    ev_type,
                    virtio_media::V4L2_EVENT_SOURCE_CHANGE,
                    changes,
                    if own { "" } else { " (routed to its owner)" }
                ),
            );
            if ev_type == virtio_media::V4L2_EVENT_SOURCE_CHANGE {
                let mut new_fmt = [0u8; virtio_media::V4L2_FORMAT_SIZE];
                virtio_media::write_u32(
                    &mut new_fmt,
                    virtio_media::V4L2_FORMAT_TYPE,
                    virtio_media::V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                );
                let mut out_fmt = [0u8; 256];
                if do_ioctl(
                    mmio,
                    q0,
                    req_base,
                    resp,
                    host,
                    virtio_media::V4L2_IOCTL_G_FMT,
                    &new_fmt,
                    &mut out_fmt,
                    log,
                )
                .is_ok()
                {
                    log_fmt("G_FMT CAPTURE after SOURCE_CHANGE", &out_fmt, log);
                    let w = virtio_media::read_u32(&out_fmt, virtio_media::V4L2_FORMAT_WIDTH);
                    let h = virtio_media::read_u32(&out_fmt, virtio_media::V4L2_FORMAT_HEIGHT);
                    let size = virtio_media::read_u32(&out_fmt, virtio_media::V4L2_FORMAT_SIZEIMAGE);
                    let stride = virtio_media::read_u32(&out_fmt, virtio_media::V4L2_FORMAT_BYTESPERLINE);
                    let fourcc = virtio_media::read_u32(&out_fmt, virtio_media::V4L2_FORMAT_PIXELFORMAT);
                    // HEVC-MAIN10: the CAPTURE queue this session mapped its
                    // buffers from was sized for cfg.capture_fourcc.  A format
                    // change here (e.g. a host that would now offer P010) cannot
                    // be adopted mid-stream -- the MMAPed buffers keep their old
                    // length -- so say so and keep the negotiated layout; a new
                    // session (FLUSH/OPEN) negotiates afresh.
                    if fourcc != 0 && fourcc != cfg.capture_fourcc {
                        let mut line = virtio_media::LineBuf::new();
                        let _ = write!(
                            line,
                            "SOURCE_CHANGE: capture fourcc 0x{:08X} ({}) differs from the negotiated {}; keeping the mapped layout (a new session renegotiates)",
                            fourcc,
                            capture_fourcc_name(fourcc),
                            capture_fourcc_name(cfg.capture_fourcc)
                        );
                        vlog(log, format_args!("{}", line.as_str()));
                    }
                    if w != 0 && h != 0 {
                        cfg.width = w;
                        cfg.height = h;
                    }
                    if size != 0 {
                        cfg.capture_sizeimage = size;
                    }
                    if stride != 0 {
                        cfg.capture_stride = stride;
                    }
                }
            }
            if !own {
                *routed = routed.saturating_add(1);
            }
            Pump::Handled
        }
        Note::Error(errno) => {
            vlog(
                log,
                format_args!(
                    "ERROR event: session {} errno={} ({}){}",
                    host,
                    errno,
                    -errno,
                    if own { "" } else { " (latched for its owner)" }
                ),
            );
            if own {
                return Pump::Error(errno);
            }
            *event_err = errno;
            *routed = routed.saturating_add(1);
            Pump::Handled
        }
        Note::Ignored(what) => {
            vlog(
                log,
                format_args!("event: session {} kind/type {} ignored", host, what),
            );
            Pump::Handled
        }
    }
}

/// Consume at most one eventq entry and apply it to the session it belongs to.
///
/// PER-SESSION-LIVESTATE (1.0.0.25): the host tags every event with the session
/// it belongs to.  An event for the session whose IOCTL is running behaves
/// exactly as before; an event for the **other** session of the same function is
/// now applied to that session (see [`Fanout`]) instead of being dropped --
/// dropping it is what starved the first session's OUTPUT buffers and failed its
/// next BeginFrame in the Edge + PotPlayer run (doc 37).
unsafe fn pump_event(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    cfg: &mut SessionConfig,
    fan: &mut Fanout,
    log: &mut dyn virtio_media::Log,
) -> Pump {
    if mmio.harvest_events().is_err() { return Pump::Error(-5); }
    let Some(saved) = mmio.events.as_mut().and_then(|e| e.pop()) else {
        return Pump::Idle;
    };
    if !mmio.events.as_ref().unwrap().owner_current(saved.owner) {
        return Pump::Handled; // stale generation, never retarget recycled host id
    }
    let mut result = Pump::Handled;
    let own_host = fan.own_host;
    {
        let ev_session = saved.owner.host;
        let note = saved.note;
        if ev_session == own_host {
            result = apply_note(
                mmio, q0, req_base, resp, ev_session, true, cfg, None, &mut 0, &mut 0, note, log,
            );
        } else {
            // PER-SESSION-LIVESTATE: deliver it to the session the host named.
            let mut delivered = false;
            if let Some(peer) = fan.peer.as_deref_mut() {
                if peer.open && peer.host_id == ev_session {
                    let routed_before = peer.routed;
                    result = apply_note(
                        mmio,
                        q0,
                        req_base,
                        resp,
                        ev_session,
                        false,
                        &mut peer.cfg,
                        Some(&mut peer.frames),
                        &mut peer.event_err,
                        &mut peer.routed,
                        note,
                        log,
                    );
                    delivered = true;
                    // One line per routed batch, not per event: the IOCTL ring is
                    // 30 000 characters and a 1080p session emits two events per
                    // frame.
                    if peer.routed != routed_before
                        && (peer.routed <= 4 || peer.routed % 240 == 0)
                    {
                        let mut line = virtio_media::LineBuf::new();
                        let _ = write!(
                            line,
                            "DISPATCH: session {} event {} applied to token {} (host session {}), {} routed completion(s) so far",
                            own_host, ev_session, peer.token, peer.host_id, peer.routed
                        );
                        vlog(log, format_args!("{}", line.as_str()));
                    }
                    result = match result {
                        // A routed frame/error is not this handler's to return.
                        Pump::Frame(_, _) | Pump::Error(_) => Pump::Handled,
                        other => other,
                    };
                }
            }
            if !delivered {
                vlog(
                    log,
                    format_args!(
                        "event for session {} (ours {}) belongs to no live session -> dropped",
                        ev_session, own_host
                    ),
                );
            }
        }
    }
    // DMA descriptor was already returned by pure harvest, before any command.
    result
}

/// Wait for the next `DQBUF(CAPTURE)` and return `(index, bytesused)`.
///
/// P-BATCH ZEROCOPY: this is `take_frame`'s original wait loop, lifted out
/// unchanged so the staged path (`take_frame`) and the mapped path
/// (`map_frame`) wait exactly the same way and one can never silently drift
/// from the other.
pub(crate) unsafe fn poll_frame(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    fan: &mut Fanout,
    cfg: &mut SessionConfig,
    pending: &mut PendingFrames,
    timeout_ms: u32,
    log: &mut dyn virtio_media::Log,
) -> Result<(u32, u32), virtio_media::Error> {
    let max_spins = timeout_ms.saturating_mul(2).max(1).min(60_000);
    let mut spins = 0u32;
    let mut frame_index: Option<u32> = None;
    let mut frame_bytesused = 0u32;

    while frame_index.is_none() {
        // A frame that SEND met while waiting for a free OUTPUT buffer comes
        // first: one GET_FRAME per DQBUF(CAPTURE), in arrival order.
        if let Some((index, used)) = pending.pop() {
            frame_index = Some(index);
            frame_bytesused = used;
            break;
        }
        match pump_event(mmio, q0, req_base, resp, cfg, fan, log) {
            Pump::Frame(index, used) => {
                frame_index = Some(index);
                frame_bytesused = used;
            }
            Pump::Error(errno) => return Err(virtio_media::Error::Errno(errno)),
            Pump::Handled => {}
            Pump::Idle => {
                spins += 1;
                if spins >= max_spins {
                    vlog(
                        log,
                        format_args!(
                            "eventq TIMEOUT: no DQBUF(CAPTURE) after {} spins; last_used={} avail={}",
                            spins, mmio.events.as_ref().map_or(0, |e| e.q1.last_used),
                            mmio.events.as_ref().map_or(0, |e| e.q1.last_avail)
                        ),
                    );
                    return Err(virtio_media::Error::EventTimeout(spins));
                }
                irq::wait(mmio.wdf_device);
            }
        }
    }
    Ok((frame_index.unwrap(), frame_bytesused))
}

/// Bytes per row of the negotiated CAPTURE layout: `width` samples of 1 byte
/// (NV12) or 2 bytes (P010, 10 bits MSB-aligned in each 16-bit word).  The Y and
/// the interleaved UV plane share this row length; the UV plane starts at
/// `stride * height` and is half as tall.
pub(crate) fn capture_row_bytes(cfg: &SessionConfig) -> usize {
    cfg.width as usize * capture_bytes_per_sample(cfg.capture_fourcc) as usize
}

/// Poll the eventq for `DQBUF(CAPTURE)`, then copy the tight frame image into
/// `out` (the caller's GET_FRAME output, after the VM_FRAME_INFO header).
///
/// P3/1.0.0.10: the CAPTURE buffer is queued again right after the copy, so the
/// session keeps decoding for as long as the client keeps sending access units
/// (the one-shot P2-1 path never reused a buffer).
pub(crate) unsafe fn take_frame(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    fan: &mut Fanout,
    cfg: &mut SessionConfig,
    pending: &mut PendingFrames,
    out: &mut [u8],
    timeout_ms: u32,
    log: &mut dyn virtio_media::Log,
) -> Result<vmedia_abi::VM_FRAME_INFO, virtio_media::Error> {
    let t_wait0 = qpc_now();
    let (index, frame_bytesused) =
        poll_frame(mmio, q0, req_base, resp, fan, cfg, pending, timeout_ms, log)?;

    let index = index as usize;
    let t_got = qpc_now();
    if index >= cfg.capture_count as usize {
        return Err(virtio_media::Error::EventIndex(index as u32));
    }
    let tight = capture_row_bytes(cfg) * (cfg.height as usize) * 3 / 2;
    let frame_va = cfg.cap_va[index];
    let frame_len = cfg.cap_len[index] as usize;
    let bytesused = frame_bytesused as usize;
    if frame_va.is_null() || frame_len < tight {
        vlog(
            log,
            format_args!("capture[{}] too small: len={} need={}", index, frame_len, tight),
        );
        requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log);
        return Err(virtio_media::Error::ShortFrame(frame_len, tight));
    }
    if bytesused < tight {
        vlog(
            log,
            format_args!(
                "capture[{}] DQBUF bytesused={} < {} tight {} (stride={})",
                index, bytesused,
                capture_fourcc_name(cfg.capture_fourcc), tight, cfg.capture_stride
            ),
        );
        requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log);
        return Err(virtio_media::Error::ShortFrame(bytesused, tight));
    }
    if out.len() < tight {
        vlog(
            log,
            format_args!("GET_FRAME output {} bytes < frame {}", out.len(), tight),
        );
        requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log);
        return Err(virtio_media::Error::ShortFrame(out.len(), tight));
    }

    // Copy the tight image (row-copy when the stride is padded).  `row_bytes` is
    // width samples of 1 (NV12) or 2 (P010) bytes; both planes use it.
    //
    // 1.0.0.23 CACHED-POOL: the pool is a *cached* mapping now and the host
    // wrote these pixels, so the window has to be invalidated before we read it.
    // This is the staged path (the UMD normally uses MAP_FRAME); it stays here
    // as the fallback, and it is the one that used to cost 30 ms per 1080p copy.
    let mut inv_us = 0.0f64;
    if POOL_CACHED.load(Ordering::SeqCst) {
        let t_inv0 = qpc_now();
        cache_invalidate_range(frame_va, frame_len);
        inv_us = qpc_us_between(t_inv0, qpc_now());
    }
    let t_read0 = qpc_now();
    let row_bytes = capture_row_bytes(cfg);
    if cfg.capture_stride as usize == row_bytes {
        ptr::copy_nonoverlapping(frame_va, out.as_mut_ptr(), tight);
    } else {
        for y in 0..cfg.height as usize {
            let row = core::slice::from_raw_parts(
                frame_va.add(y * cfg.capture_stride as usize),
                row_bytes,
            );
            out[y * row_bytes..(y + 1) * row_bytes].copy_from_slice(row);
        }
        let uv_base = cfg.capture_stride as usize * cfg.height as usize;
        let out_uv = row_bytes * cfg.height as usize;
        for y in 0..(cfg.height as usize / 2) {
            let row = core::slice::from_raw_parts(
                frame_va.add(uv_base + y * cfg.capture_stride as usize),
                row_bytes,
            );
            out[out_uv + y * row_bytes..out_uv + (y + 1) * row_bytes].copy_from_slice(row);
        }
    }

    // The pixels are in `out` now; hand the buffer back for the next frame.
    let t_copy = qpc_now();
    requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log);
    let t_requeue = qpc_now();

    vlog(
        log,
        format_args!(
            "FRAME OK: index={} {} geometry={}x{} stride={} size={} bytesused={} tight={} cap_queued=0x{:X}",
            index, capture_fourcc_name(cfg.capture_fourcc), cfg.width, cfg.height,
            cfg.capture_stride, cfg.capture_sizeimage, bytesused, tight, cfg.cap_queued
        ),
    );

    let info = vmedia_abi::VM_FRAME_INFO {
        Width: cfg.width,
        Height: cfg.height,
        Stride: cfg.capture_stride,
        Size: tight as u32,
        BytesUsed: bytesused as u32,
        FourCC: cfg.capture_fourcc,
        SessionId: fan.own_host,
        Index: index as u32,
    };
    // 1.0.0.12 diagnostics: where the GET_FRAME time goes. `wait` is the host
    // decode the client is paying for, `copy` is the NV12 pull out of the pool
    // (`inv` is the cache invalidate that pull needs since 1.0.0.23, when the
    // pool stopped being PAGE_NOCACHE), `requeue` is the one synchronous command
    // left in the frame path.  Logged for the first frames and every 60th.
    if !qpc_zero(t_got) && (cfg.aus_queued <= 3 || cfg.aus_queued % 60 == 0) {
        vlog(
            log,
            format_args!(
                "GET timing: wait={:.2} ms copy={:.2} ms inv={:.1} us requeue={:.2} ms (frame {} index {})",
                qpc_ms_between(t_wait0, t_got),
                qpc_ms_between(t_read0, t_copy),
                inv_us,
                qpc_ms_between(t_copy, t_requeue),
                cfg.aus_queued,
                index
            ),
        );
    }
    Ok(info)
}

/// P-BATCH ZEROCOPY: wait for the next decoded frame and map the capture
/// buffer's **pool pages** into the calling process instead of copying them.
///
/// Why this is safe without a copy: the `media_host` pool is ordinary guest RAM
/// at a known guest-physical base (`pool_pa`).  The device writes the decoded
/// frame (NV12, or P010 since HEVC-MAIN10) into a buffer carved out of that pool
/// by `VIRTIO_MEDIA_CMD_MMAP`; `DQBUF(CAPTURE)` says it is complete.  While the
/// buffer is checked out of the device (`QBUF` is deferred to
/// [`unmap_frame`]/RELEASE_FRAME) the host cannot write into it again, so the
/// caller may read the pixels in place.
///
/// The mapping is built exactly like `gpu-wddm`'s guest backing
/// (`MdlOwned::from_locked_pfns` + `mm_map_locked_pages_specify_cache` in user
/// mode): an MDL over the pool's PFNs, mapped into the current process.  Since
/// 1.0.0.23 it is **`MmCached`** (it was `MmNonCached` up to 1.0.0.22): a
/// noncached read of one 1080p NV12 frame cost 30.35 ms, a cached one is two
/// orders of magnitude cheaper -- paid for by invalidating the window here,
/// after `DQBUF` and before the caller can read it.  See the cache-maintenance
/// comment at the top of this file for the API choice and the ordering rules.
///
/// Errors leave the capture buffer requeued (so a failed mapping costs a frame,
/// not the session) and the caller falls back to the staged `GET_FRAME` path.
pub(crate) unsafe fn map_frame(
    mmio: &mut Kmmio,
    q0: &mut virtio_media::Queue,
    req_base: &virtio_media::Buf,
    resp: &virtio_media::Buf,
    fan: &mut Fanout,
    cfg: &mut SessionConfig,
    pending: &mut PendingFrames,
    pool_va: *mut u8,
    pool_pa: u64,
    pool_len: usize,
    timeout_ms: u32,
    tagged: bool,
    log: &mut dyn virtio_media::Log,
) -> Result<(MappedFrame, vmedia_abi::VM_FRAME_INFO), virtio_media::Error> {
    const PAGE: usize = 4096;
    let t_wait0 = qpc_now();
    let (index, frame_bytesused) =
        poll_frame(mmio, q0, req_base, resp, fan, cfg, pending, timeout_ms, log)?;
    let t_got = qpc_now();
    let index = index as usize;
    if index >= cfg.capture_count as usize {
        return Err(virtio_media::Error::EventIndex(index as u32));
    }
    let tight = capture_row_bytes(cfg) * (cfg.height as usize) * 3 / 2;
    let frame_len = cfg.cap_len[index] as usize;
    let bytesused = frame_bytesused as usize;
    if cfg.cap_va[index].is_null() || frame_len < tight {
        vlog(
            log,
            format_args!("map capture[{}] too small: len={} need={}", index, frame_len, tight),
        );
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::ShortFrame(frame_len, tight));
    }
    if bytesused < tight {
        vlog(
            log,
            format_args!(
                "map capture[{}] DQBUF bytesused={} < {} tight {} (stride={})",
                index, bytesused,
                capture_fourcc_name(cfg.capture_fourcc), tight, cfg.capture_stride
            ),
        );
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::ShortFrame(bytesused, tight));
    }
    if pool_pa == 0 {
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::PoolMissing);
    }

    // Page-align the window: MMAP offsets are page-aligned in practice, but a
    // mapping that started inside a page would be wrong, so round down and keep
    // the delta for the caller.
    //
    // The pool position is what VIRTIO_MEDIA_CMD_MMAP answered (`cap_addr`), NOT
    // QUERYBUF's `mem_offset` (`cap_off`): the host's address allocator decides
    // where the range lands, and `cap_va` is built from exactly this address.  A
    // window taken at `cap_off` could point at another buffer's pixels (or past
    // the pool) whenever the two differ.
    let off = cfg.cap_addr[index] as usize;
    let map_off = off & !(PAGE - 1);
    let delta = off - map_off;
    let Some(map_len) = delta
        .checked_add(frame_len)
        .and_then(|n| n.checked_add(PAGE - 1))
        .map(|n| n & !(PAGE - 1))
    else {
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::PoolTooSmall(0, pool_len as u64));
    };
    if map_len == 0 || map_off.checked_add(map_len).map(|end| end > pool_len).unwrap_or(true) {
        vlog(
            log,
            format_args!(
                "map capture[{}]: pool window 0x{:X}+0x{:X} outside the pool (0x{:X} bytes)",
                index, map_off, map_len, pool_len
            ),
        );
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::PoolTooSmall(
            (map_off + map_len) as u64,
            pool_len as u64,
        ));
    }

    // PFNs of the pool window. `from_locked_pfns` sets MDL_PAGES_LOCKED and
    // fills the PFN array, which is what makes the MDL mappable in user mode; it
    // takes no reference on the pages, so freeing it never frees pool memory.
    let first_pfn = (pool_pa >> 12) + (map_off as u64 >> 12);
    let pages = map_len >> 12;
    let mut pfns: Vec<u64> = Vec::new();
    if pfns.try_reserve_exact(pages).is_err() {
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::NoMemoryResources);
    }
    for i in 0..pages {
        pfns.push(first_pfn + i as u64);
    }
    let mdl = match wdk::wdm::MdlOwned::from_locked_pfns(&pfns) {
        Ok(mdl) => mdl,
        Err(_) => {
            vlog(log, format_args!("map capture[{}]: MdlOwned::from_locked_pfns failed", index));
            if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
            return Err(virtio_media::Error::NoMemoryResources);
        }
    };
    // 1.0.0.23 CACHED-POOL: the caller reads these pixels, so the window is
    // mapped cached.  A platform that refuses the cached attribute still gets a
    // working (slow, never-stale) noncached window instead of a failed frame.
    let mut user_cached = true;
    let mut mapped = match microseh::try_seh(|| {
        wdk::wdm::mm_map_locked_pages_specify_cache(
            &mdl,
            true,
            wdk::wdm::MEMORY_CACHING_TYPE::MmCached,
            None,
        )
    }) {
        Ok(Some(va)) => Some(va),
        Ok(None) => None,
        Err(_) => {
            vlog(log, format_args!("map capture[{}]: user mapping raised", index));
            if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
            return Err(virtio_media::Error::NoMemoryResources);
        }
    };
    if mapped.is_none() {
        user_cached = false;
        vlog(
            log,
            format_args!("map capture[{}]: MmCached window refused, retrying MmNonCached", index),
        );
        mapped = match microseh::try_seh(|| {
            wdk::wdm::mm_map_locked_pages_specify_cache(
                &mdl,
                true,
                wdk::wdm::MEMORY_CACHING_TYPE::MmNonCached,
                None,
            )
        }) {
            Ok(Some(va)) => Some(va),
            Ok(None) => None,
            Err(_) => {
                vlog(log, format_args!("map capture[{}]: user mapping raised (noncached)", index));
                if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
                return Err(virtio_media::Error::NoMemoryResources);
            }
        };
    }
    let Some(va) = mapped else {
        vlog(log, format_args!("map capture[{}]: user mapping refused", index));
        if tagged { pending.push(index as u32, frame_bytesused); } else { requeue_capture(mmio, q0, req_base, resp, fan.own_host, cfg, index, log); }
        return Err(virtio_media::Error::NoMemoryResources);
    };

    // Host wrote the pixels, the caller is about to read them: discard any
    // cached copy of the window *before* handing the VA out.  Done through the
    // pool's kernel mapping -- same physical lines (the caches are physically
    // indexed), and it keeps the maintenance in kernel space even though the
    // address space belongs to the caller.
    let mut inv_us = 0.0f64;
    if user_cached && POOL_CACHED.load(Ordering::SeqCst) && !pool_va.is_null() {
        let t_inv0 = qpc_now();
        cache_invalidate_range(pool_va.add(map_off), map_len);
        inv_us = qpc_us_between(t_inv0, qpc_now());
    }

    let t_mapped = qpc_now();
    vlog(
        log,
        format_args!(
            "MAP_FRAME ok: frame index {} {} {:.2} ms wait + {:.2} ms map, uva=0x{:X} window=0x{:X}+0x{:X} ({} pages, {}), cache_invalidate={:.1} us, bytesused={} tight={}",
            index,
            capture_fourcc_name(cfg.capture_fourcc),
            qpc_ms_between(t_wait0, t_got),
            qpc_ms_between(t_got, t_mapped),
            va.as_ptr() as usize,
            map_off,
            map_len,
            pages,
            if user_cached { "cached" } else { "noncached" },
            inv_us,
            bytesused,
            tight
        ),
    );
    let info = vmedia_abi::VM_FRAME_INFO {
        Width: cfg.width,
        Height: cfg.height,
        Stride: cfg.capture_stride,
        Size: tight as u32,
        BytesUsed: bytesused as u32,
        FourCC: cfg.capture_fourcc,
        SessionId: fan.own_host,
        Index: index as u32,
    };
    Ok((
        MappedFrame { mdl, va, len: map_len as u32, index: index as u32, delta: delta as u32 },
        info,
    ))
}

/// P-BATCH ZEROCOPY: tear the user mapping down.  Must run in the process that
/// called [`map_frame`] (a user VA belongs to one address space).  The capture
/// buffer itself is requeued by the caller (`RELEASE_FRAME`), not here.
pub(crate) unsafe fn unmap_frame(m: MappedFrame) {
    wdk::wdm::mm_unmap_locked_pages(&m.mdl, m.va);
    // `m.mdl` drops here: IoFreeMdl only, the pool pages stay the pool's.
}

fn qpc_zero(t: u64) -> bool {
    t == 0
}
