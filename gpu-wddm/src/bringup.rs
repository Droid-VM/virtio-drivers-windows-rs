//! Opt-in startup diagnostics, readable over SSH after a failed PnP start.
//! The test installer creates Services\VirtioGpu\Parameters\Bringup first.

/// Runtime checkpoints must also work at DISPATCH_LEVEL and in the ISR.
/// Capture only atomics there; publish from the private adapter query, which
/// remains reachable even when device creation is blocked. Snapshot fields
/// are independent observations, not a transaction across worker threads.
pub mod runtime {
    #[derive(Clone, Copy)]
    pub enum Stat {
        CreateDeviceEnter, CreateDeviceOk, CreateProcessEnter, CreateProcessOk,
        EscapeEnter, EscapeReturn, SubmitEnter, SubmitReturn,
        IrqEnter, IrqHandled, DpcEnter, DpcReturn,
        ControlWake, ControlResponsesDone, ControlRequestsDone,
        DmaCompleteEnter, DmaCompleteReturn, NotifyEnter, NotifyReturn,
        // Blt present local-copy eligibility (kmd-blt-present-plan.md P0).
        // Counted only; behavior is unchanged until P1.
        PresentEnter, PresentLocalEligible, PresentLocalManySubRects,
        PresentLocalIneligibleFlags, PresentLocalIneligibleNotGuestBlob,
        PresentLocalIneligibleNoInfo, PresentLocalIneligibleTiled,
        PresentLocalIneligibleStride, PresentLocalIneligibleFormatUnsupported,
        PresentLocalIneligibleScaled,
        PresentLocalIneligibleBounds, PresentLocalIneligibleDstNotAttached,
        StdAllocSharedPrimary, StdAllocShadow, StdAllocStaging, StdAllocOther,
        // P1: fast path actually taken / mapping failed (fell back) / copies run.
        PresentLocalTaken, PresentLocalMapFail, LocalCopyDone, LocalCopySyncFallback,
        Count,
    }

    /// Last-seen values, overwritten on every hit; published next to the counters.
    #[derive(Clone, Copy)]
    pub enum Slot {
        PresentLastSrcFormat, PresentLastDstFormat,
        PresentLastSrcStride, PresentLastDstStride,
        PresentLastSrcModifierLo, PresentLastDstModifierLo,
        PresentLastSrcWidth, PresentLastSrcHeight,
        PresentLastDstWidth, PresentLastDstHeight,
        PresentLastSubRectCnt, PresentLastCoverWidth, PresentLastCoverHeight,
        PresentLastSrcBlobMem, PresentLastDstBlobMem,
        /// 1 = guest blob, 2 = classic 3D (standard allocation), 0 = other.
        PresentLastSrcKind, PresentLastDstKind,
        PresentLastDst3dFlags, PresentLastDstLayoutStride, PresentLastDstAttachedBytes,
        PresentLocalCopyOption, LocalCopyLastUs, LocalCopyMaxUs, LocalCopyQueueMax,
        LocalCopyLastSwizzle,
        Count,
    }

    #[cfg(feature = "bringup-diagnostics")]
    use core::sync::atomic::{AtomicU32, Ordering};
    #[cfg(feature = "bringup-diagnostics")]
    static COUNTERS: [AtomicU32; Stat::Count as usize] =
        [const { AtomicU32::new(0) }; Stat::Count as usize];
    #[cfg(feature = "bringup-diagnostics")]
    static FENCES: [[AtomicU32; 64]; 3] =
        [const { [const { AtomicU32::new(0) }; 64] }; 3];
    #[cfg(feature = "bringup-diagnostics")]
    static SLOTS: [AtomicU32; Slot::Count as usize] =
        [const { AtomicU32::new(0) }; Slot::Count as usize];

    #[inline]
    pub fn hit(stat: Stat) {
        #[cfg(feature = "bringup-diagnostics")]
        COUNTERS[stat as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn set(slot: Slot, value: u32) {
        #[cfg(feature = "bringup-diagnostics")]
        SLOTS[slot as usize].store(value, Ordering::Relaxed);
    }

    #[inline]
    pub fn set_max(slot: Slot, value: u32) {
        #[cfg(feature = "bringup-diagnostics")]
        SLOTS[slot as usize].fetch_max(value, Ordering::Relaxed);
    }

    /// phase: 0 submitted, 1 response callback, 2 notify returned successfully.
    #[inline]
    pub fn fence(phase: usize, node: u32, value: u32) {
        #[cfg(feature = "bringup-diagnostics")]
        if let Some(slot) = FENCES.get(phase).and_then(|nodes| nodes.get(node as usize)) {
            slot.store(value, Ordering::Relaxed);
        }
    }

    pub fn publish() {
        #[cfg(feature = "bringup-diagnostics")]
        {
            if unsafe { wdk::wdm::KeGetCurrentIrql() } != 0 { return; }
            const NAMES: [&str; Stat::Count as usize] = [
                "RtCreateDeviceEnter", "RtCreateDeviceOk", "RtCreateProcessEnter", "RtCreateProcessOk",
                "RtEscapeEnter", "RtEscapeReturn", "RtSubmitEnter", "RtSubmitReturn",
                "RtIrqEnter", "RtIrqHandled", "RtDpcEnter", "RtDpcReturn",
                "RtControlWake", "RtControlResponsesDone", "RtControlRequestsDone",
                "RtDmaCompleteEnter", "RtDmaCompleteReturn", "RtNotifyEnter", "RtNotifyReturn",
                "RtPresentEnter", "RtPresentLocalEligible", "RtPresentLocalManySubRects",
                "RtPresentLocalIneligibleFlags", "RtPresentLocalIneligibleNotGuestBlob",
                "RtPresentLocalIneligibleNoInfo", "RtPresentLocalIneligibleTiled",
                "RtPresentLocalIneligibleStride", "RtPresentLocalIneligibleFormatUnsupported",
                "RtPresentLocalIneligibleScaled",
                "RtPresentLocalIneligibleBounds", "RtPresentLocalIneligibleDstNotAttached",
                "RtStdAllocSharedPrimary", "RtStdAllocShadow", "RtStdAllocStaging", "RtStdAllocOther",
                "RtPresentLocalTaken", "RtPresentLocalMapFail", "RtLocalCopyDone", "RtLocalCopySyncFallback",
            ];
            const SLOT_NAMES: [&str; Slot::Count as usize] = [
                "RtPresentLastSrcFormat", "RtPresentLastDstFormat",
                "RtPresentLastSrcStride", "RtPresentLastDstStride",
                "RtPresentLastSrcModifierLo", "RtPresentLastDstModifierLo",
                "RtPresentLastSrcWidth", "RtPresentLastSrcHeight",
                "RtPresentLastDstWidth", "RtPresentLastDstHeight",
                "RtPresentLastSubRectCnt", "RtPresentLastCoverWidth", "RtPresentLastCoverHeight",
                "RtPresentLastSrcBlobMem", "RtPresentLastDstBlobMem",
                "RtPresentLastSrcKind", "RtPresentLastDstKind",
                "RtPresentLastDst3dFlags", "RtPresentLastDstLayoutStride", "RtPresentLastDstAttachedBytes",
                "RtPresentLocalCopyOption", "RtLocalCopyLastUs", "RtLocalCopyMaxUs", "RtLocalCopyQueueMax",
                "RtLocalCopyLastSwizzle",
            ];
            super::record("RuntimeDiagnosticsRevision", 989);
            for (name, counter) in NAMES.iter().zip(COUNTERS.iter()) {
                super::record(name, counter.load(Ordering::Relaxed));
            }
            for (name, slot) in SLOT_NAMES.iter().zip(SLOTS.iter()) {
                super::record(name, slot.load(Ordering::Relaxed));
            }
            for node in 0..64 {
                let values = core::array::from_fn::<_, 3, _>(|phase| FENCES[phase][node].load(Ordering::Relaxed));
                if values.iter().any(|&v| v != 0) {
                    for (phase, value) in values.iter().enumerate() {
                        super::record(&alloc::format!("RtFence{node:02}_{}", ["Submit", "Response", "Notify"][phase]), *value);
                    }
                }
            }
        }
    }
}

/// Read a REG_DWORD from `Services\VirtioGpu\Parameters`. PASSIVE_LEVEL only
/// (returns None otherwise); the key is optional, so a missing value is None.
pub fn read_parameter(name: &str) -> Option<u32> {
    use core::{mem::zeroed, ptr::null_mut};
    use wdk::wdm::*;
    if unsafe { KeGetCurrentIrql() } != 0 { return None; }
    let mut path: alloc::vec::Vec<u16> = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VirtioGpu\\Parameters".encode_utf16().collect();
    let mut key_name = UNICODE_STRING {
        Length: (path.len() * 2) as u16,
        MaximumLength: (path.len() * 2) as u16,
        Buffer: path.as_mut_ptr(),
    };
    let mut attrs: OBJECT_ATTRIBUTES = unsafe { zeroed() };
    attrs.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    attrs.ObjectName = &mut key_name;
    attrs.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    let mut handle = null_mut();
    let status = unsafe { ZwOpenKey(&mut handle, KEY_QUERY_VALUE, &mut attrs) };
    if (status as i32) < 0 { return None; }
    let mut name_buf: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let mut value_name = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    // KEY_VALUE_PARTIAL_INFORMATION: TitleIndex, Type, DataLength, Data[]
    let mut buf = [0u32; 8];
    let mut result_len = 0u32;
    let status = unsafe {
        ZwQueryValueKey(handle, &mut value_name, KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation,
                        buf.as_mut_ptr().cast(), size_of_val(&buf) as u32, &mut result_len)
    };
    unsafe { ZwClose(handle); }
    if (status as i32) < 0 || buf[1] != REG_DWORD || buf[2] < 4 { return None; }
    Some(buf[3])
}

#[cfg(not(feature = "bringup-diagnostics"))]
pub fn record(_name: &str, _value: u32) {}

#[cfg(not(feature = "bringup-diagnostics"))]
pub fn event(_name: &str, _value: u32) {}

#[cfg(not(feature = "bringup-diagnostics"))]
pub fn count(_name: &str, _counter: &core::sync::atomic::AtomicU32) {}

/// Publish a running total instead of a flag. `record` overwrites, so a repeated
/// call site cannot be told apart from a single one; the allocation paths need
/// the distinction to attribute a failure to this driver or to dxgkrnl.
#[cfg(feature = "bringup-diagnostics")]
pub fn count(name: &str, counter: &core::sync::atomic::AtomicU32) {
    use core::sync::atomic::Ordering;
    let value = counter.fetch_add(1, Ordering::Relaxed) + 1;
    record(name, value);
}

/// Preserve callback order without unbounded registry growth. These diagnostics
/// deliberately skip callbacks above PASSIVE_LEVEL, like `record` does.
#[cfg(feature = "bringup-diagnostics")]
pub fn event(name: &str, value: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static SEQUENCE: AtomicU32 = AtomicU32::new(0);
    if unsafe { wdk::wdm::KeGetCurrentIrql() } != 0 { return; }
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    if sequence < 256 {
        record(&alloc::format!("Event{sequence:03}_{name}"), value);
    }
}

#[cfg(feature = "bringup-diagnostics")]
pub fn record(name: &str, value: u32) {
    use core::{mem::zeroed, ptr::null_mut};
    use wdk::wdm::*;
    // Registry APIs require PASSIVE_LEVEL. Never change callback behavior just
    // to emit a diagnostic, and never log an error recursively from this path.
    if unsafe { KeGetCurrentIrql() } != 0 { return; }
    let mut path: alloc::vec::Vec<u16> = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\VirtioGpu\\Parameters\\Bringup".encode_utf16().collect();
    let mut key_name = UNICODE_STRING {
        Length: (path.len() * 2) as u16,
        MaximumLength: (path.len() * 2) as u16,
        Buffer: path.as_mut_ptr(),
    };
    let mut attrs: OBJECT_ATTRIBUTES = unsafe { zeroed() };
    attrs.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    attrs.ObjectName = &mut key_name;
    attrs.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
    let mut handle = null_mut();
    let status = unsafe { ZwOpenKey(&mut handle, KEY_SET_VALUE, &mut attrs) };
    if (status as i32) < 0 { return; }
    let mut name_buf: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let mut value_name = UNICODE_STRING {
        Length: (name_buf.len() * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
        Buffer: name_buf.as_mut_ptr(),
    };
    unsafe {
        ZwSetValueKey(handle, &mut value_name, 0, REG_DWORD,
                      (&value as *const u32).cast_mut().cast(), size_of::<u32>() as u32);
        ZwClose(handle);
    }
}
