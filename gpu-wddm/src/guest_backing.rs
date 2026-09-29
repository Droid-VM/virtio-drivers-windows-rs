//! Windows-owned contiguous backing for guest-allocated DRM BOs.
//! The current pseudo-unprotected VM shares ordinary guest RAM with the host.
//! Keep pages and the MDL alive until RESOURCE_UNREF and allocation teardown.
use core::ptr::{NonNull, null_mut};
use spin::mutex::SpinMutex;
use winresult::STATUS;
use crate::NtStatus;
use wdk::wdm::*;
use core::sync::atomic::AtomicU32;
use crate::bringup;
use alloc::vec::Vec;
use core::mem::ManuallyDrop;
use virtio_drivers::device::gpu::commands::MemEntry;
#[path = "guest_backing_layout.rs"]
mod layout;

static ALLOC_OK: AtomicU32 = AtomicU32::new(0);
static CONTIG_FAIL: AtomicU32 = AtomicU32::new(0);
static MDL_FAIL: AtomicU32 = AtomicU32::new(0);
static FREED: AtomicU32 = AtomicU32::new(0);
static RETAINED_MAPPED: AtomicU32 = AtomicU32::new(0);
static CHUNK_OK: AtomicU32 = AtomicU32::new(0);
static DEFERRED: AtomicU32 = AtomicU32::new(0);
static REAPED: AtomicU32 = AtomicU32::new(0);
static DROP_UNMAP: AtomicU32 = AtomicU32::new(0);
static CHUNK_FAIL: AtomicU32 = AtomicU32::new(0);

fn record_alloc_failure(stage: u32, size: u64) {
    bringup::record("GuestBackingFailStage", stage);
    bringup::record("GuestBackingFailSize", size as u32);
    bringup::record("GuestBackingFailPid", unsafe { PsGetCurrentProcessId() as usize as u32 });
}

// Each mapping owns a referenced process object, not a reusable PID. A
// nonblocking wait on that object proves address-space teardown has completed.
struct DeferredBacking {
    allocation: Option<NonNull<u8>>,
    mdl: *mut MDL,
    process: usize,
}
unsafe impl Send for DeferredBacking {}
static DEFERRED_BACKINGS: SpinMutex<Vec<DeferredBacking>> = SpinMutex::new(Vec::new());

fn process_exited(process: usize) -> bool {
    let mut timeout = LARGE_INTEGER { QuadPart: 0 };
    unsafe { KeWaitForSingleObject(process as _, KWAIT_REASON::Executive,
        MODE::KernelMode.0 as _, 0, &mut timeout) == STATUS::SUCCESS.to_u32() }
}

unsafe fn free_backing(allocation: Option<NonNull<u8>>, mdl: *mut MDL) {
    unsafe {
        if let Some(raw) = allocation {
            MmFreeContiguousMemory(raw.as_ptr() as _);
            IoFreeMdl(mdl);
        } else {
            MmFreePagesFromMdl(mdl);
            ExFreePool(mdl as _);
        }
    }
}

// Called by the PASSIVE_LEVEL control worker and before new allocations.
// Never wait for a live process or issue GPU commands from this reaper.
pub fn reap_exited_backings() {
    loop {
        let retired = {
            let mut pending = DEFERRED_BACKINGS.lock();
            pending.iter().position(|b| process_exited(b.process))
                .map(|index| pending.swap_remove(index))
        };
        let Some(retired) = retired else { break; };
        unsafe {
            free_backing(retired.allocation, retired.mdl);
            ObfDereferenceObject(retired.process as _);
        }
        bringup::count("GuestBackingReapedCount", &REAPED);
        bringup::count("GuestBackingFreedCount", &FREED);
    }
}

pub struct GuestBacking {
    // None means pages and MDL came from MmAllocatePagesForMdlEx, whose
    // matching free routines differ from IoAllocateMdl/contiguous memory.
    allocation: Option<NonNull<u8>>,
    pub physical: u64,
    pub size: u32,
    mdl: ManuallyDrop<MdlOwned>,
    entries: Vec<MemEntry>,
    mapping: SpinMutex<Option<(NonNull<u8>, usize)>>,
    // Contiguous backing already has a kernel VA (pool pointer); the chunked
    // form gets a lazily created kernel mapping of its MDL for the present
    // local-copy path. Unmapped in Drop before the pages go away.
    kernel_va: Option<NonNull<u8>>,
    kernel_map: SpinMutex<Option<NonNull<u8>>>,
}
unsafe impl Send for GuestBacking {}
unsafe impl Sync for GuestBacking {}
impl core::fmt::Debug for GuestBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestBacking").field("physical", &self.physical)
            .field("size", &self.size).finish()
    }
}

impl GuestBacking {
    pub fn new(size: u64) -> Result<Self, NtStatus> {
        reap_exited_backings();
        // A 64 KiB-aligned start works with 4/16/64 KiB host pages. Vulkan/DXVK
        // commonly reports a 4 KiB-aligned allocation size, while the guest
        // backing protocol needs 64 KiB segments. Keep the logical blob size
        // unchanged in Allocation/RESOURCE_CREATE_BLOB and pad only this
        // physical backing; the host consumes entries only for the requested
        // range. Reject overflow before rounding.
        const ALIGN: u64 = 65536;
        let Some(size) = size.checked_add(ALIGN - 1).map(|size| size & !(ALIGN - 1)) else {
            return Err(NtStatus(STATUS::INVALID_PARAMETER));
        };
        if size == 0 || size > u32::MAX as u64 {
            return Err(NtStatus(STATUS::INVALID_PARAMETER));
        }
        // Large BOs only require contiguous 64 KiB DMA segments, not one
        // contiguous range for the entire allocation. Avoid the expensive
        // whole-range search/reclaim on fragmented guest RAM. The chunked
        // path also supplies the MDL used for CPU mappings and teardown.
        if size >= 2 * 1024 * 1024 {
            return Self::new_chunked(size);
        }
        let Some(raw) = NonNull::new(unsafe {
            MmAllocateContiguousMemory((size + ALIGN) as _,
                LARGE_INTEGER { QuadPart: 0xFFFFFFFFFF }) as *mut u8
        }) else {
            bringup::count("GuestBackingContigFailCount", &CONTIG_FAIL);
            record_alloc_failure(1, size);
            return Self::new_chunked(size);
        };
        let physical = mm_get_physical_address(raw.as_ptr() as _);
        let offset = ((ALIGN - (physical & (ALIGN - 1))) & (ALIGN - 1)) as usize;
        let ptr = unsafe { raw.as_ptr().add(offset) };
        unsafe { core::ptr::write_bytes(ptr, 0, size as usize); }
        let mdl = unsafe { IoAllocateMdl(ptr as _, size as u32, 0, 0, null_mut()) };
        if mdl.is_null() {
            unsafe { MmFreeContiguousMemory(raw.as_ptr() as _); }
            bringup::count("GuestBackingMdlFailCount", &MDL_FAIL);
            record_alloc_failure(2, size);
            return Err(NtStatus(STATUS::NO_MEMORY));
        }
        unsafe { MmBuildMdlForNonPagedPool(mdl); }
        let mut backing = Self { allocation: Some(raw), physical: physical + offset as u64,
            size: size as u32, mdl: ManuallyDrop::new(MdlOwned(mdl)),
            entries: Vec::new(), mapping: SpinMutex::new(None),
            kernel_va: NonNull::new(ptr), kernel_map: SpinMutex::new(None) };
        backing.entries.try_reserve_exact(1)?;
        backing.entries.push(MemEntry { addr: backing.physical, length: backing.size, _padding: 0 });
        backing.record_success();
        Ok(backing)
    }

    fn new_chunked(size: u64) -> Result<Self, NtStatus> {
        const CHUNK: usize = layout::CHUNK_SIZE;
        // RESOURCE_CREATE_BLOB uses owned DMA storage for multi-page lists,
        // so large BOs need not fit all 64 KiB segments into one command page.
        // The first attempt must stay nonblocking because this function is also
        // reachable from allocation callbacks that may be latency-sensitive.
        // CreateAllocation runs at PASSIVE_LEVEL, though, so a transiently
        // fragmented page allocator can be retried with reclaim enabled before
        // reporting a false GPU out-of-memory error to the UMD.
        const FLAGS: u32 = MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS | MM_ALLOCATE_FULLY_REQUIRED;
        let mut mdl = unsafe { MmAllocatePagesForMdlEx(
            LARGE_INTEGER { QuadPart: 0 }, LARGE_INTEGER { QuadPart: 0xFFFFFFFFFF },
            LARGE_INTEGER { QuadPart: CHUNK as i64 }, size as _,
            MEMORY_CACHING_TYPE::MmCached, FLAGS | MM_ALLOCATE_NO_WAIT,
        ) };
        if mdl.is_null() && unsafe { KeGetCurrentIrql() } as u32 <= PASSIVE_LEVEL {
            mdl = unsafe { MmAllocatePagesForMdlEx(
                LARGE_INTEGER { QuadPart: 0 }, LARGE_INTEGER { QuadPart: 0xFFFFFFFFFF },
                LARGE_INTEGER { QuadPart: CHUNK as i64 }, size as _,
                MEMORY_CACHING_TYPE::MmCached, FLAGS,
            ) };
        }
        if mdl.is_null() {
            bringup::count("GuestBackingChunkFailCount", &CHUNK_FAIL);
            record_alloc_failure(3, size);
            return Err(NtStatus(STATUS::NO_MEMORY));
        }
        // The API zeroes pages by default. Keep its MDL for user mapping; no
        // contiguous kernel VA mapping or manual PFN construction is needed.
        let mut backing = Self { allocation: None, physical: 0, size: size as u32,
            mdl: ManuallyDrop::new(MdlOwned(mdl)), entries: Vec::new(),
            mapping: SpinMutex::new(None),
            kernel_va: None, kernel_map: SpinMutex::new(None) };
        if unsafe { (*mdl).ByteCount as u64 != size || (*mdl).ByteOffset != 0 } {
            return Err(NtStatus(STATUS::INVALID_DEVICE_STATE));
        }
        backing.entries.try_reserve_exact(size as usize / CHUNK)?;
        let pages = backing.mdl.physical_pages();
        if !layout::valid_chunks(pages, size as usize, PAGE_SIZE as usize) {
            return Err(NtStatus(STATUS::INVALID_DEVICE_STATE));
        }
        for chunk in pages.chunks_exact(CHUNK / PAGE_SIZE as usize) {
            let addr = chunk[0] * PAGE_SIZE as u64;
            backing.entries.push(MemEntry { addr, length: CHUNK as u32, _padding: 0 });
        }
        backing.physical = backing.entries[0].addr;
        bringup::count("GuestBackingChunkOkCount", &CHUNK_OK);
        bringup::record("GuestBackingLastChunkEntries", backing.entries.len() as u32);
        backing.record_success();
        Ok(backing)
    }

    fn record_success(&self) {
        bringup::count("GuestBackingOkCount", &ALLOC_OK);
        bringup::record("GuestBackingLastOkSize", self.size);
    }

    pub fn entries(&self) -> &[MemEntry] { &self.entries }

    /// Kernel-mode VA of the whole backing (cached). IRQL <= DISPATCH_LEVEL.
    pub fn kernel_address(&self) -> Result<NonNull<u8>, NtStatus> {
        if let Some(ptr) = self.kernel_va { return Ok(ptr); }
        let mut map = self.kernel_map.lock();
        if let Some(ptr) = *map { return Ok(ptr); }
        let ptr = match microseh::try_seh(|| mm_map_locked_pages_specify_cache(
            &self.mdl, false, MEMORY_CACHING_TYPE::MmCached, None)) {
            Ok(Some(ptr)) => ptr,
            Ok(None) => return Err(NtStatus(STATUS::NO_MEMORY)),
            Err(e) => return Err(e.into()),
        };
        *map = Some(ptr);
        Ok(ptr)
    }

    pub fn map(&self) -> Result<NonNull<u8>, NtStatus> {
        let mut mapping = self.mapping.lock();
        if mapping.is_some() { return Err(NtStatus(STATUS::ALREADY_COMMITTED)); }
        let ptr = match microseh::try_seh(|| mm_map_locked_pages_specify_cache(
            &self.mdl, true, MEMORY_CACHING_TYPE::MmCached, None)) {
            Ok(Some(ptr)) => ptr,
            Ok(None) => return Err(NtStatus(STATUS::NO_MEMORY)),
            Err(e) => return Err(e.into()),
        };
        let process = unsafe { IoGetCurrentProcess() };
        unsafe { ObfReferenceObject(process as _); }
        *mapping = Some((ptr, process as usize));
        Ok(ptr)
    }

    pub fn unmap(&self, ptr: NonNull<u8>) -> Result<(), NtStatus> {
        let mut mapping = self.mapping.lock();
        if *mapping != Some((ptr, unsafe { IoGetCurrentProcess() as usize })) {
            return Err(NtStatus(STATUS::INVALID_PARAMETER));
        }
        mm_unmap_locked_pages(&self.mdl, ptr);
        let (_, process) = mapping.take().unwrap();
        unsafe { ObfDereferenceObject(process as _); }
        Ok(())
    }
}

impl Drop for GuestBacking {
    fn drop(&mut self) {
        // Kernel mappings are process-independent; drop them first so neither
        // the immediate free nor the deferred retirement leaves a live VA.
        if let Some(ptr) = self.kernel_map.get_mut().take() {
            mm_unmap_locked_pages(&self.mdl, ptr);
        }
        if let Some((ptr, process)) = self.mapping.get_mut().take() {
            if process == unsafe { IoGetCurrentProcess() as usize }
                && unsafe { KeGetCurrentIrql() } as u32 <= APC_LEVEL
            {
                mm_unmap_locked_pages(&self.mdl, ptr);
                unsafe { ObfDereferenceObject(process as _); }
                bringup::count("GuestBackingDropUnmapCount", &DROP_UNMAP);
            } else {
                // Host access has already been retired by RESOURCE_UNREF (on
                // unref error Allocation retains an Arc instead of dropping).
                // Preserve the pages until the user VA can no longer exist.
                let retired = DeferredBacking {
                    allocation: self.allocation, mdl: self.mdl.0, process,
                };
                let queued = {
                    let mut pending = DEFERRED_BACKINGS.lock();
                    if pending.try_reserve(1).is_ok() {
                        pending.push(retired);
                        true
                    } else { false }
                };
                if queued {
                    bringup::count("GuestBackingDeferredCount", &DEFERRED);
                } else {
                    // Under extreme pool pressure retaining remains safer
                    // than freeing RAM with a live mapping. Keep diagnostics.
                    bringup::count("GuestBackingRetainedMappedCount", &RETAINED_MAPPED);
                    bringup::record("GuestBackingLastRetainedSize", self.size);
                }
                return;
            }
        }
        unsafe { free_backing(self.allocation, self.mdl.0); }
        bringup::count("GuestBackingFreedCount", &FREED);
    }
}
