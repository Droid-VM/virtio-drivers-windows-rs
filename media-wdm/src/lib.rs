//! virtio-media Windows guest driver (KMDF, ARM64) - P1c-3 bring-up.
//!
//! P1c-1 bound a KMDF function driver to the two `PCI\VEN_1AF4&DEV_1070`
//! functions that crosvm exposes for `--virtio-media kind=decoder|encoder`.
//! P1c-2 added the virtio 1.x bring-up, but it reached the device through PCI
//! configuration space (`BUS_INTERFACE_STANDARD`), which this guest does not
//! hand to the driver. P1c-3 removes that dependency completely:
//!
//!   1. `EvtDevicePrepareHardware` walks `ResourcesTranslated`, maps every
//!      `CmResourceTypeMemory` BAR with `MmMapIoSpaceEx(PAGE_READWRITE)`,
//!   2. the virtio common config is found inside the mapped BARs (feature
//!      bit 32 + two sane queues), and common/ISR/device/notify use the
//!      standard settings-BAR offsets 0x0/0x1000/0x2000/0x3000,
//!   3. negotiate `VIRTIO_F_VERSION_1`,
//!   4. program commandq (0) and eventq (1), 256 entries each,
//!   5. submit a real `VIRTIO_MEDIA_CMD_OPEN` request and poll the used ring,
//!   6. log every step to the kernel debugger and to the driver's registry key,
//!   7. reset the device, and unmap the BARs in `EvtDeviceReleaseHardware`.
//!
//! There is **no PCI config-space read or write anywhere** in this driver.
//! Interrupts are deliberately not used: MSI-X is left at NO_VECTOR and the
//! used ring is polled.
//!
//! The register/queue/protocol logic lives in `virtio_media.rs`; the platform
//! glue (resource list, mapping, layout probing) lives here.

#![no_std]
#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    unused,
    static_mut_refs,
    unsafe_op_in_unsafe_fn
)]

extern crate alloc;

use alloc::vec::Vec;

use core::fmt::Write as _;
use core::mem::{size_of, transmute, zeroed};
use core::ptr;

use winresult::STATUS;
use wdk::wdf as wdf;
use wdk::wdm as wdm;

mod virtio_media;

/// PCI identity of a virtio-media function: VIRTIO_ID_MEDIA (48) + 0x1040.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_PCI_MEDIA_DEVICE_ID: u16 = 0x1070;

const DEVPROP_TYPE_STRING: u32 = 0x0000_0012;
/// DEVPKEY_Device_FriendlyName -{a45c254e-df1c-4efd-8020-67d146a850e0}, 14.
const DEVPKEY_DEVICE_FRIENDLY_NAME: wdm::DEVPROPKEY = wdm::DEVPROPKEY {
    fmtid: wdm::DEVPROPGUID {
        Data1: 0xa45c_254e,
        Data2: 0xdf1c,
        Data3: 0x4efd,
        Data4: [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
    },
    pid: 14,
};

const FRIENDLY_NAME: &[u8] = b"DroidVM Video Media";

/// WDF function-table dispatch (the C headers use `FORCEINLINE` wrappers that
/// bindgen does not emit, exactly like `wdk::wdf::WdfDriverCreate` does it).
macro_rules! wdf_table_fn {
    ($pfn:ty, $index:ident) => {{
        unsafe {
            transmute::<wdf::WDFFUNC, $pfn>(*wdf::WdfFunctions_01027.add(wdf::WDFFUNCENUM::$index.0 as usize))
        }
    }};
}

/// The `wdk` crate pulls in `alloc`; a driver has to supply the kernel pool
/// backed allocator (same one `gpu-wddm` uses).
#[global_allocator]
static GLOBAL_ALLOC: wdk::wdm::WdkAllocator = wdk::wdm::WdkAllocator;

/// Emit one pre-formatted line to the kernel debugger (`DbgPrint` is variadic and
/// the format string has to be NUL terminated).
fn dbg_line(msg: &[u8]) {
    let mut buf = [0u8; 256];
    let n = msg.len().min(buf.len() - 3);
    buf[..n].copy_from_slice(&msg[..n]);
    buf[n] = b'\r';
    buf[n + 1] = b'\n';
    buf[n + 2] = 0;
    unsafe { wdm::DbgPrint(b"[virtio-media] %s\0".as_ptr() as *const i8, buf.as_ptr() as *const i8) };
}

/// Log sink: copies every line to DbgPrint and to a registry blob that can be
/// read from the guest without a kernel debugger.
struct KernelLog {
    buf: Vec<u8>,
}

impl KernelLog {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(8192) }
    }

    fn finish(&self, device: wdf::WDFDEVICE) {
        let len = self.buf.len().min(6000);
        if len == 0 {
            return;
        }
        let mut utf16: Vec<u16> = Vec::with_capacity(len + 1);
        for &b in &self.buf[..len] {
            utf16.push(b as u16);
        }
        utf16.push(0);
        let mut value = wdf::UNICODE_STRING {
            Length: ((utf16.len() - 1) * 2) as u16,
            MaximumLength: (utf16.len() * 2) as u16,
            Buffer: utf16.as_mut_ptr(),
        };
        let mut name_buf: [u16; 16] = [0; 16];
        for (i, b) in b"VirtioMediaLog".iter().enumerate() {
            name_buf[i] = *b as u16;
        }
        let mut name = wdf::UNICODE_STRING {
            Length: (name_buf.len() as u16 - 1) * 2,
            MaximumLength: (name_buf.len() as u16) * 2,
            Buffer: name_buf.as_mut_ptr(),
        };

        unsafe {
            let mut key: wdf::WDFKEY = ptr::null_mut();
            let Some(open) = wdf_table_fn!(wdf::PFN_WDFDEVICEOPENREGISTRYKEY, WdfDeviceOpenRegistryKeyTableIndex)
            else {
                return;
            };
            let status = open(
                wdf::WdfDriverGlobals,
                device,
                wdm::PLUGPLAY_REGKEY_DRIVER,
                wdm::KEY_SET_VALUE as u32,
                ptr::null_mut(),
                &mut key,
            );
            if !winresult::NtStatus::from(status).is_success() {
                dbg_line(b"log: could not open the driver registry key (log stays in DbgPrint)");
                return;
            }
            if let Some(assign) =
                wdf_table_fn!(wdf::PFN_WDFREGISTRYASSIGNUNICODESTRING, WdfRegistryAssignUnicodeStringTableIndex)
            {
                let status = assign(wdf::WdfDriverGlobals, key, &name as *const _, &value as *const _);
                if !winresult::NtStatus::from(status).is_success() {
                    dbg_line(b"log: WdfRegistryAssignUnicodeString failed");
                }
            }
            if let Some(close) = wdf_table_fn!(wdf::PFN_WDFREGISTRYCLOSE, WdfRegistryCloseTableIndex) {
                close(wdf::WdfDriverGlobals, key);
            }
        }
    }
}

impl virtio_media::Log for KernelLog {
    fn line(&mut self, s: &str) {
        dbg_line(s.as_bytes());
        if self.buf.len() + s.len() + 2 <= 8192 {
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.extend_from_slice(b"\r\n");
        }
    }
}

fn ntstatus(result: Result<(), winresult::NtStatus>) -> u32 {
    match result {
        Ok(()) => STATUS::SUCCESS.to_u32(),
        Err(status) => status.to_u32(),
    }
}

fn check(raw: u32) -> Result<(), winresult::NtStatus> {
    let status = winresult::NtStatus::from(raw);
    if status.is_success() && status != STATUS::TIMEOUT {
        Ok(())
    } else {
        Err(status)
    }
}

unsafe fn wdf_device_create(
    device_init: *mut wdf::PWDFDEVICE_INIT,
    device: *mut wdf::WDFDEVICE,
    attributes: wdf::PWDF_OBJECT_ATTRIBUTES,
) -> Result<(), winresult::NtStatus> {
    let pfn: wdf::PFN_WDFDEVICECREATE = wdf_table_fn!(wdf::PFN_WDFDEVICECREATE, WdfDeviceCreateTableIndex);
    match pfn {
        Some(pfn) => check(pfn(wdf::WdfDriverGlobals, device_init, attributes, device)),
        None => Err(STATUS::INVALID_DEVICE_REQUEST),
    }
}

unsafe fn wdf_device_wdm_get_physical_device(device: wdf::WDFDEVICE) -> wdm::PDEVICE_OBJECT {
    let pfn: wdf::PFN_WDFDEVICEWDMGETPHYSICALDEVICE =
        wdf_table_fn!(wdf::PFN_WDFDEVICEWDMGETPHYSICALDEVICE, WdfDeviceWdmGetPhysicalDeviceTableIndex);
    match pfn {
        Some(pfn) => pfn(wdf::WdfDriverGlobals, device) as wdm::PDEVICE_OBJECT,
        None => ptr::null_mut(),
    }
}

unsafe fn wdf_device_init_set_pnp_callbacks(
    device_init: wdf::PWDFDEVICE_INIT,
    callbacks: &mut wdf::WDF_PNPPOWER_EVENT_CALLBACKS,
) {
    let pfn: wdf::PFN_WDFDEVICEINITSETPNPPOWEREVENTCALLBACKS = wdf_table_fn!(
        wdf::PFN_WDFDEVICEINITSETPNPPOWEREVENTCALLBACKS,
        WdfDeviceInitSetPnpPowerEventCallbacksTableIndex
    );
    if let Some(pfn) = pfn {
        pfn(wdf::WdfDriverGlobals, device_init, callbacks);
    }
}

/// `WdfDeviceQueryProperty` with an ASCII-out conversion, used for the PnP identity
/// strings (`DevicePropertyHardwareID`).
unsafe fn query_ascii_property(
    device: wdf::WDFDEVICE,
    property: wdf::DEVICE_REGISTRY_PROPERTY,
    out: &mut [u8; 260],
) -> usize {
    let pfn: wdf::PFN_WDFDEVICEQUERYPROPERTY =
        wdf_table_fn!(wdf::PFN_WDFDEVICEQUERYPROPERTY, WdfDeviceQueryPropertyTableIndex);
    let Some(pfn) = pfn else { return 0 };

    let mut utf16 = [0u16; 260];
    let mut len: u32 = 0;
    let raw = pfn(
        wdf::WdfDriverGlobals,
        device,
        property,
        (utf16.len() * 2) as u32,
        utf16.as_mut_ptr() as *mut core::ffi::c_void,
        &mut len,
    );
    if check(raw).is_err() {
        return 0;
    }

    let chars = (len as usize / 2).min(utf16.len());
    let mut n = 0;
    for &c in &utf16[..chars] {
        let b = if c == 0 {
            break;
        } else if c < 0x80 {
            c as u8
        } else {
            b'?'
        };
        if n >= out.len() - 1 {
            break;
        }
        out[n] = b;
        n += 1;
    }
    n
}

/// Stamp `DEVPKEY_Device_FriendlyName` on the devnode.
unsafe fn set_friendly_name(device: wdf::WDFDEVICE) {
    let pdo = wdf_device_wdm_get_physical_device(device);
    if pdo.is_null() {
        return;
    }

    let mut name = [0u16; 64];
    let mut n = 0;
    for &b in FRIENDLY_NAME {
        if n + 1 >= name.len() {
            break;
        }
        name[n] = b as u16;
        n += 1;
    }
    name[n] = 0;
    let bytes = (n + 1) * 2;

    let raw = wdm::IoSetDevicePropertyData(
        pdo,
        &DEVPKEY_DEVICE_FRIENDLY_NAME,
        0,
        0,
        DEVPROP_TYPE_STRING,
        bytes as u32,
        name.as_mut_ptr() as *mut core::ffi::c_void,
    );
    match check(raw) {
        Ok(()) => dbg_line(b"friendly name set to \"DroidVM Video Media\""),
        Err(_) => dbg_line(b"friendly name left to the INF (IoSetDevicePropertyData refused)"),
    }
}

// ---------------------------------------------------------------------------
// P1c-3: resource-list based BAR mapping (no PCI config space access)
// ---------------------------------------------------------------------------

const MAX_MAPPED_BARS: usize = 8;
const MAX_SLOTS: usize = 8;
/// Map at most the first 64 KiB of each BAR: enough for the four virtio
/// structures at 0x0/0x1000/0x2000/0x3000 even when the BAR is the (large)
/// shared-memory BAR.
const MAX_MAP_BYTES: u64 = 0x1_0000;
const MAX_PROBE_BYTES: usize = 0x1_0000;

#[derive(Clone, Copy)]
struct MappedBar {
    va: *mut u8,
    pa: u64,
    map_len: usize,
    bar_len: usize,
}

const EMPTY_BAR: MappedBar = MappedBar { va: ptr::null_mut(), pa: 0, map_len: 0, bar_len: 0 };

#[derive(Clone, Copy)]
struct DevSlot {
    device: wdf::WDFDEVICE,
    bars: [MappedBar; MAX_MAPPED_BARS],
    count: usize,
}

const EMPTY_SLOT: DevSlot =
    DevSlot { device: ptr::null_mut(), bars: [EMPTY_BAR; MAX_MAPPED_BARS], count: 0 };

static mut SLOTS: [DevSlot; MAX_SLOTS] = [EMPTY_SLOT; MAX_SLOTS];
static mut SLOTS_LOCK: wdm::KSPIN_LOCK = 0;

fn vlog(log: &mut dyn virtio_media::Log, args: core::fmt::Arguments<'_>) {
    virtio_media::log_args(log, args);
}

unsafe fn slots_lock() -> wdm::KIRQL {
    unsafe { wdm::KeAcquireSpinLockRaiseToDpc(ptr::addr_of_mut!(SLOTS_LOCK)) }
}

unsafe fn slots_unlock(irql: wdm::KIRQL) {
    unsafe { wdm::KeReleaseSpinLock(ptr::addr_of_mut!(SLOTS_LOCK), irql) }
}

/// Find the slot owned by `device`, or claim a free one.
unsafe fn slot_claim(device: wdf::WDFDEVICE) -> Option<usize> {
    let irql = unsafe { slots_lock() };
    let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
    let mut found = None;
    let mut free = None;
    for i in 0..MAX_SLOTS {
        let s = unsafe { &*slots.add(i) };
        if !s.device.is_null() && s.device == device {
            found = Some(i);
            break;
        }
        if s.device.is_null() && free.is_none() {
            free = Some(i);
        }
    }
    let idx = found.or(free);
    if let Some(i) = idx {
        if found.is_none() {
            unsafe {
                *slots.add(i) = EMPTY_SLOT;
                (*slots.add(i)).device = device;
            }
        }
    }
    unsafe { slots_unlock(irql) };
    idx
}

unsafe fn slot_lookup(device: wdf::WDFDEVICE) -> Option<usize> {
    let irql = unsafe { slots_lock() };
    let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
    let mut found = None;
    for i in 0..MAX_SLOTS {
        let s = unsafe { &*slots.add(i) };
        if !s.device.is_null() && s.device == device {
            found = Some(i);
            break;
        }
    }
    unsafe { slots_unlock(irql) };
    found
}

/// Unmap every BAR owned by a slot and clear it. Returns how many were mapped.
unsafe fn slot_take(idx: usize, log: &mut dyn virtio_media::Log) -> usize {
    let mut copy = [EMPTY_BAR; MAX_MAPPED_BARS];
    let count;
    let irql = unsafe { slots_lock() };
    {
        let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
        let slot = unsafe { &mut *slots.add(idx) };
        count = slot.count;
        copy[..count].copy_from_slice(&slot.bars[..count]);
        *slot = EMPTY_SLOT;
    }
    unsafe { slots_unlock(irql) };

    for (i, b) in copy[..count].iter().enumerate() {
        if b.va.is_null() {
            continue;
        }
        unsafe { wdm::MmUnmapIoSpace(b.va as *mut core::ffi::c_void, b.map_len as u64) };
        vlog(
            log,
            format_args!("unmap mem{} pa=0x{:X} len=0x{:X} (MmUnmapIoSpace)", i, b.pa, b.map_len),
        );
    }
    count
}

/// Walk `ResourcesTranslated`, map every memory descriptor with
/// `MmMapIoSpaceEx(PAGE_READWRITE|PAGE_NOCACHE)` and remember the mappings in
/// the device's slot. Nothing here touches PCI configuration space.
unsafe fn map_translated_resources(
    list: wdf::WDFCMRESLIST,
    slot_idx: usize,
    log: &mut dyn virtio_media::Log,
) -> Result<usize, virtio_media::Error> {
    let Some(get_count) = wdf_table_fn!(
        wdf::PFN_WDFCMRESOURCELISTGETCOUNT,
        WdfCmResourceListGetCountTableIndex
    ) else {
        vlog(log, format_args!("WdfCmResourceListGetCount unavailable"));
        return Err(virtio_media::Error::NoMemoryResources);
    };
    let Some(get_desc) = wdf_table_fn!(
        wdf::PFN_WDFCMRESOURCELISTGETDESCRIPTOR,
        WdfCmResourceListGetDescriptorTableIndex
    ) else {
        vlog(log, format_args!("WdfCmResourceListGetDescriptor unavailable"));
        return Err(virtio_media::Error::NoMemoryResources);
    };

    let n = get_count(wdf::WdfDriverGlobals, list);
    vlog(log, format_args!("resources: translated list count={}", n));

    let mut mapped = 0usize;
    for i in 0..n {
        let desc = get_desc(wdf::WdfDriverGlobals, list, i);
        if desc.is_null() {
            continue;
        }
        let typ = unsafe { (*desc).Type as u32 };
        if typ != wdm::CmResourceTypeMemory {
            vlog(log, format_args!("res[{}] type={} (not memory, skipped)", i, typ));
            continue;
        }

        let start = unsafe { (*desc).u.Memory.Start.QuadPart as u64 };
        let length = unsafe { (*desc).u.Memory.Length as u64 };
        let flags = unsafe { (*desc).Flags };
        vlog(
            log,
            format_args!(
                "res[{}] memory pa=0x{:X} len=0x{:X} flags=0x{:04X}",
                i, start, length, flags
            ),
        );
        if start == 0 || length == 0 {
            vlog(log, format_args!("res[{}] is not backed by an assigned BAR, skipped", i));
            continue;
        }
        if mapped >= MAX_MAPPED_BARS {
            vlog(log, format_args!("more than {} memory BARs, stopping", MAX_MAPPED_BARS));
            break;
        }

        let rounded = (length + 0xFFF) & !0xFFF;
        let map_len = core::cmp::min(rounded, MAX_MAP_BYTES) as usize;
        let mut va = unsafe {
            wdm::MmMapIoSpaceEx(
                wdm::PHYSICAL_ADDRESS { QuadPart: start as i64 },
                map_len as u64,
                wdm::PAGE_READWRITE | wdm::PAGE_NOCACHE,
            ) as *mut u8
        };
        if va.is_null() {
            // Some ARM64 platforms reject PAGE_NOCACHE for device memory; the
            // resource list is the authority here, so retry with PAGE_READWRITE.
            vlog(
                log,
                format_args!("res[{}] PAGE_READWRITE|PAGE_NOCACHE refused, retrying PAGE_READWRITE", i),
            );
            va = unsafe {
                wdm::MmMapIoSpaceEx(
                    wdm::PHYSICAL_ADDRESS { QuadPart: start as i64 },
                    map_len as u64,
                    wdm::PAGE_READWRITE,
                ) as *mut u8
            };
        }
        if va.is_null() {
            vlog(log, format_args!("res[{}] MmMapIoSpaceEx(0x{:X}, 0x{:X}) failed", i, start, map_len));
            return Err(virtio_media::Error::MapFailed(mapped as u8));
        }

        let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
        unsafe {
            let slot = &mut *slots.add(slot_idx);
            slot.bars[mapped] =
                MappedBar { va, pa: start, map_len, bar_len: length as usize };
            slot.count = mapped + 1;
        }
        vlog(
            log,
            format_args!(
                "map mem{}: pa=0x{:X} len=0x{:X} -> va=0x{:X} (PAGE_READWRITE|PAGE_NOCACHE)",
                mapped, start, map_len, va as usize
            ),
        );
        mapped += 1;
    }

    if mapped == 0 {
        return Err(virtio_media::Error::NoMemoryResources);
    }
    Ok(mapped)
}

unsafe fn read8(p: *mut u8, off: u32) -> u8 {
    unsafe { ptr::read_volatile(p.add(off as usize)) }
}

unsafe fn read16(p: *mut u8, off: u32) -> u16 {
    unsafe { ptr::read_volatile(p.add(off as usize) as *const u16) }
}

unsafe fn read32(p: *mut u8, off: u32) -> u32 {
    unsafe { ptr::read_volatile(p.add(off as usize) as *const u32) }
}

unsafe fn write16(p: *mut u8, off: u32, v: u16) {
    unsafe { ptr::write_volatile(p.add(off as usize) as *mut u16, v) }
}

unsafe fn write32(p: *mut u8, off: u32, v: u32) {
    unsafe { ptr::write_volatile(p.add(off as usize) as *mut u32, v) }
}

/// Does a virtio `common_cfg` start at `p`?
///
/// The signature is intentionally narrow: `num_queues` must be 1..=64, the
/// device must offer `VIRTIO_F_VERSION_1` (feature bit 32), and both queue 0
/// and queue 1 must report a power-of-two size and a sane notify offset.
fn probe_common_at(p: *mut u8) -> Option<u16> {
    // Read-only pre-check first: it keeps the probe from writing into a BAR
    // that only looks like a common config (device config, shmem, ...).
    let num_queues = unsafe { read16(p, 0x12) };
    if num_queues == 0 || num_queues > 64 {
        return None;
    }
    let device_status = unsafe { read8(p, 0x14) };
    if device_status & !(1 | 2 | 4 | 8 | 64 | 128) != 0 {
        return None;
    }
    if unsafe { read8(p, 0x15) } > 0x20 {
        return None;
    }

    // Read the 64-bit device feature word through feature_select 0/1.
    unsafe {
        write32(p, 0x00, 0);
        let _lo = read32(p, 0x04);
        write32(p, 0x00, 1);
        let hi = read32(p, 0x04);
        write32(p, 0x00, 0);
        if hi & 1 == 0 {
            return None;
        }

        write16(p, 0x16, 0);
        let size0 = read16(p, 0x18);
        let notify0 = read16(p, 0x1e);
        write16(p, 0x16, 1);
        let size1 = read16(p, 0x18);
        let notify1 = read16(p, 0x1e);
        write16(p, 0x16, 0);

        let ok = |s: u16| s >= 8 && s.is_power_of_two() && s <= 32768;
        if !ok(size0) || !ok(size1) || notify0 >= 0x1000 || notify1 >= 0x1000 {
            return None;
        }
    }
    Some(num_queues)
}

/// Locate the virtio common config inside the mapped BARs and derive the cap
/// table from the standard settings-BAR layout (common x, ISR x+0x1000,
/// device x+0x2000, notify x+0x3000). Returns the memory-resource index, the
/// common-config offset and the cap table.
unsafe fn discover_layout(
    bars: &[MappedBar],
    log: &mut dyn virtio_media::Log,
) -> Result<(usize, u32, virtio_media::Caps), virtio_media::Error> {
    for step in [0x1000usize, 0x100usize] {
        for (i, b) in bars.iter().enumerate() {
            let usable = core::cmp::min(b.bar_len, b.map_len);
            if usable < 0x40 {
                continue;
            }
            let limit = core::cmp::min(usable, MAX_PROBE_BYTES);
            let mut off = 0usize;
            while off + 0x40 <= limit {
                if let Some(num_queues) = unsafe { probe_common_at(b.va.add(off)) } {
                    vlog(
                        log,
                        format_args!(
                            "bar probe: common @ mem{}+0x{:X} (num_queues={}, VERSION_1 offered)",
                            i, off, num_queues
                        ),
                    );
                    let usable32 = core::cmp::min(usable, u32::MAX as usize) as u32;
                    let caps = virtio_media::Caps::single_bar_layout(i as u8, off as u32, usable32)?;
                    return Ok((i, off as u32, caps));
                }
                off += step;
            }
        }
    }
    Err(virtio_media::Error::NoCommonConfig)
}

/// Kernel implementation of the virtio MMIO accessors (volatile, noncached).
struct Kmmio {
    common: *mut u8,
    notify: *mut u8,
    device: *mut u8,
}

impl virtio_media::Mmio for Kmmio {
    fn common_read_u8(&self, off: u32) -> u8 {
        unsafe { ptr::read_volatile(self.common.add(off as usize)) }
    }
    fn common_read_u16(&self, off: u32) -> u16 {
        unsafe { ptr::read_volatile(self.common.add(off as usize) as *const u16) }
    }
    fn common_read_u32(&self, off: u32) -> u32 {
        unsafe { ptr::read_volatile(self.common.add(off as usize) as *const u32) }
    }
    fn common_write_u8(&mut self, off: u32, v: u8) {
        unsafe { ptr::write_volatile(self.common.add(off as usize), v) }
    }
    fn common_write_u16(&mut self, off: u32, v: u16) {
        unsafe { ptr::write_volatile(self.common.add(off as usize) as *mut u16, v) }
    }
    fn common_write_u32(&mut self, off: u32, v: u32) {
        unsafe { ptr::write_volatile(self.common.add(off as usize) as *mut u32, v) }
    }
    fn notify(&mut self, off: u32, value: u16) {
        unsafe { ptr::write_volatile(self.notify.add(off as usize) as *mut u16, value) }
    }
    fn device_read_u8(&self, off: u32) -> u8 {
        if self.device.is_null() {
            return 0;
        }
        unsafe { ptr::read_volatile(self.device.add(off as usize)) }
    }
    fn device_read_u32(&self, off: u32) -> u32 {
        if self.device.is_null() {
            return 0;
        }
        unsafe { ptr::read_volatile(self.device.add(off as usize) as *const u32) }
    }
}

const QMEM_PER_QUEUE: usize = 8192;
const DMA_LEN: usize = 32768;
const REQ_OFF: usize = 16384;
const REQ_CAP: usize = 512;
const RESP_OFF: usize = 17408;
const RESP_CAP: usize = 1024;

struct Dma {
    va: *mut u8,
    pa: u64,
}

impl Dma {
    unsafe fn alloc(log: &mut dyn virtio_media::Log) -> Option<Self> {
        let va = wdm::MmAllocateContiguousMemorySpecifyCache(
            DMA_LEN as u64,
            wdm::PHYSICAL_ADDRESS { QuadPart: 0 },
            wdm::PHYSICAL_ADDRESS { QuadPart: -1 },
            wdm::PHYSICAL_ADDRESS { QuadPart: 0 },
            wdm::MEMORY_CACHING_TYPE::MmNonCached,
        );
        if va.is_null() {
            vlog(log, format_args!("MmAllocateContiguousMemorySpecifyCache({}) failed", DMA_LEN));
            return None;
        }
        let pa = wdm::MmGetPhysicalAddress(va).QuadPart as u64;
        ptr::write_bytes(va as *mut u8, 0, DMA_LEN);
        vlog(
            log,
            format_args!("dma: va=0x{:X} pa=0x{:X} len={} (noncached)", va as usize, pa, DMA_LEN),
        );
        Some(Self { va: va as *mut u8, pa })
    }
}

impl Drop for Dma {
    fn drop(&mut self) {
        unsafe {
            wdm::MmFreeContiguousMemory(self.va as *mut core::ffi::c_void);
        }
    }
}

struct Probe<'a> {
    log: &'a mut dyn virtio_media::Log,
}

impl Probe<'_> {
    unsafe fn run(
        &mut self,
        device: wdf::WDFDEVICE,
        resources: wdf::WDFCMRESLIST,
    ) -> Result<(), virtio_media::Error> {
        let log = &mut *self.log;

        let Some(slot_idx) = (unsafe { slot_claim(device) }) else {
            vlog(log, format_args!("no free device slot for BAR mappings"));
            return Err(virtio_media::Error::NoMemoryResources);
        };
        // A previous prepare without release: drop the old mappings first.
        {
            let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
            if unsafe { (*slots.add(slot_idx)).count } > 0 {
                unsafe { slot_take(slot_idx, log) };
            }
        }

        let mut bars = [EMPTY_BAR; MAX_MAPPED_BARS];
        let mut nbars = 0usize;
        let mut mmio = Kmmio {
            common: ptr::null_mut(),
            notify: ptr::null_mut(),
            device: ptr::null_mut(),
        };
        let mut dma_holder: Option<Dma> = None;

        let result = (|| {
            nbars = unsafe { map_translated_resources(resources, slot_idx, log)? };
            {
                let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
                let slot = unsafe { &*slots.add(slot_idx) };
                bars[..nbars].copy_from_slice(&slot.bars[..nbars]);
            }

            let (bar_idx, common_off, caps) = unsafe { discover_layout(&bars[..nbars], log)? };
            vlog(
                log,
                format_args!(
                    "layout: common mem{}+0x{:X} isr +0x{:X} device +0x{:X} notify +0x{:X} mult={}",
                    bar_idx,
                    common_off,
                    caps.isr.map(|r| r.offset).unwrap_or(0),
                    caps.device.map(|r| r.offset).unwrap_or(0),
                    caps.notify.offset,
                    caps.notify_off_multiplier
                ),
            );

            let bar = &bars[bar_idx];
            mmio.common = unsafe { bar.va.add(caps.common.offset as usize) };
            mmio.notify = unsafe { bar.va.add(caps.notify.offset as usize) };
            if let Some(r) = caps.device {
                mmio.device = unsafe { bar.va.add(r.offset as usize) };
            }
            vlog(
                log,
                format_args!(
                    "transport: common=0x{:X} notify=0x{:X} device=0x{:X} mult={}",
                    mmio.common as usize,
                    mmio.notify as usize,
                    mmio.device as usize,
                    caps.notify_off_multiplier
                ),
            );

            // ---- reset + feature negotiation ------------------------------
            let features = virtio_media::negotiate(&mut mmio, log)?;
            vlog(log, format_args!("negotiated features = 0x{:016X}", features));

            // ---- commandq / eventq ---------------------------------------
            let dma = dma_holder.insert(
                unsafe { Dma::alloc(log) }
                    .ok_or(virtio_media::Error::QueueMemorySmall(0, DMA_LEN))?,
            );
            let q0mem = virtio_media::VringMem {
                va: dma.va,
                pa: dma.pa,
                len: QMEM_PER_QUEUE,
            };
            let q1mem = virtio_media::VringMem {
                va: unsafe { dma.va.add(QMEM_PER_QUEUE) },
                pa: dma.pa + QMEM_PER_QUEUE as u64,
                len: QMEM_PER_QUEUE,
            };
            let mut q0 = virtio_media::setup_queue(
                &mut mmio,
                virtio_media::QUEUE_COMMAND,
                q0mem,
                virtio_media::QUEUE_DEPTH,
                caps.notify_off_multiplier,
                "commandq",
                log,
            )?;
            let _q1 = virtio_media::setup_queue(
                &mut mmio,
                virtio_media::QUEUE_EVENT,
                q1mem,
                virtio_media::QUEUE_DEPTH,
                caps.notify_off_multiplier,
                "eventq",
                log,
            )?;
            virtio_media::driver_ok(&mut mmio, log)?;

            // ---- device config -------------------------------------------
            if caps.device.is_none() {
                vlog(log, format_args!("device config capability is missing"));
                return Err(virtio_media::Error::MissingRegion("device"));
            }
            let _mcfg = virtio_media::read_media_config(&mmio, log)?;

            // ---- one real request: OPEN ----------------------------------
            let req_va = unsafe { dma.va.add(REQ_OFF) };
            let req_pa = dma.pa + REQ_OFF as u64;
            let resp_va = unsafe { dma.va.add(RESP_OFF) };
            let resp_pa = dma.pa + RESP_OFF as u64;
            let req_base = virtio_media::Buf { va: req_va, pa: req_pa, len: REQ_CAP };
            let resp = virtio_media::Buf { va: resp_va, pa: resp_pa, len: RESP_CAP };
            let mut stall = || unsafe { wdm::KeStallExecutionProcessor(500) };

            let open_req: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
            virtio_media::write_buf(&req_base, &open_req);
            vlog(log, format_args!("request: VIRTIO_MEDIA_CMD_OPEN (cmd=1, no parameters, 8 bytes)"));
            let req = virtio_media::Buf { len: 8, ..req_base };
            let used = virtio_media::submit(&mut mmio, &mut q0, &req, &resp, &mut stall, log)?;
            let mut out = [0u8; 64];
            let got = virtio_media::read_buf(&resp, &mut out);
            let n = core::cmp::min(used, got);
            let mut hex = virtio_media::LineBuf::new();
            let shown = virtio_media::hex_line(&mut hex, &out[..n], 32);
            vlog(
                log,
                format_args!(
                    "response: used.len={} bytes[{}..{}] = {}",
                    used,
                    n,
                    shown,
                    hex.as_str()
                ),
            );
            if n < 4 {
                vlog(log, format_args!("OPEN response is shorter than RespHeader ({} bytes)", n));
                return Err(virtio_media::Error::DeviceStatus(0));
            }
            let errno = i32::from_le_bytes([out[0], out[1], out[2], out[3]]);
            if errno != 0 {
                vlog(log, format_args!("OPEN failed: errno={} ({})", errno, -errno));
                return Err(virtio_media::Error::DeviceStatus(0));
            }
            let session_id = if n >= 12 {
                u32::from_le_bytes([out[8], out[9], out[10], out[11]])
            } else {
                0
            };
            vlog(
                log,
                format_args!("OPEN OK: errno=0 session_id={} (response is non-empty: {} bytes)", session_id, used),
            );

            // ---- best effort: VIDIOC_ENUM_FMT on the session ---------------
            let mut ioctl_req = [0u8; 80];
            ioctl_req[0..4].copy_from_slice(&3u32.to_le_bytes()); // VIRTIO_MEDIA_CMD_IOCTL
            // CmdHeader padding at 4..8 stays zero.
            ioctl_req[8..12].copy_from_slice(&session_id.to_le_bytes());
            ioctl_req[12..16].copy_from_slice(&virtio_media::V4L2_IOCTL_ENUM_FMT.to_le_bytes());
            ioctl_req[16..20].copy_from_slice(&0u32.to_le_bytes()); // index
            ioctl_req[20..24].copy_from_slice(&virtio_media::V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE.to_le_bytes());
            virtio_media::write_buf(&req_base, &ioctl_req);
            vlog(
                log,
                format_args!("request: VIDIOC_ENUM_FMT (ioctl=2, type=OUTPUT_MPLANE(10), index=0, 80 bytes)"),
            );
            let req = virtio_media::Buf { len: 80, ..req_base };
            match virtio_media::submit(&mut mmio, &mut q0, &req, &resp, &mut stall, log) {
                Ok(used2) => {
                    let mut out2 = [0u8; 128];
                    let got2 = virtio_media::read_buf(&resp, &mut out2);
                    let n2 = core::cmp::min(used2, got2);
                    if n2 >= 4 {
                        let errno2 = i32::from_le_bytes([out2[0], out2[1], out2[2], out2[3]]);
                        if errno2 == 0 && n2 >= 8 + 48 {
                            let pix = u32::from_le_bytes([out2[8 + 44], out2[8 + 45], out2[8 + 46], out2[8 + 47]]);
                            let fcc = fourcc(pix);
                            let fcc = core::str::from_utf8(&fcc).unwrap_or("????");
                            let mut desc = virtio_media::LineBuf::new();
                            for &b in &out2[8 + 12..8 + 44] {
                                let _ = desc.write_char(if b >= 0x20 && b < 0x7f { b as char } else { '?' });
                                if b == 0 {
                                    break;
                                }
                            }
                            vlog(
                                log,
                                format_args!(
                                    "ENUM_FMT OK: pixelformat=0x{:08X} ('{}') description=\"{}\"",
                                    pix,
                                    fcc,
                                    desc.as_str()
                                ),
                            );
                        } else {
                            vlog(log, format_args!("ENUM_FMT: errno={} len={} (not fatal)", errno2, n2));
                        }
                    }
                }
                Err(e) => vlog(log, format_args!("ENUM_FMT not answered: {} (not fatal)", e.text())),
            }

            // ---- CLOSE (the device sends no response for it) --------------
            let mut close_req = [0u8; 16];
            close_req[0..4].copy_from_slice(&2u32.to_le_bytes()); // VIRTIO_MEDIA_CMD_CLOSE
            close_req[4..8].copy_from_slice(&session_id.to_le_bytes());
            virtio_media::write_buf(&req_base, &close_req);
            let req = virtio_media::Buf { len: 16, ..req_base };
            match virtio_media::submit(&mut mmio, &mut q0, &req, &resp, &mut stall, log) {
                Ok(_) => vlog(log, format_args!("CLOSE session {} sent (no response expected)", session_id)),
                Err(e) => vlog(log, format_args!("CLOSE not answered: {}", e.text())),
            }

            Ok(())
        })();

        // ---- always quiesce the device -----------------------------------
        if !mmio.common.is_null() {
            let st = virtio_media::status(&mut mmio);
            virtio_media::set_status(&mut mmio, 0);
            vlog(
                log,
                format_args!("reset: status 0x{:02X} -> 0x{:02X}", st, virtio_media::status(&mut mmio)),
            );
        }
        // Free the vring/request buffers only after the device has been reset,
        // so it can no longer DMA into them. BAR mappings stay valid until
        // EvtDeviceReleaseHardware.
        if dma_holder.take().is_some() {
            vlog(log, format_args!("free dma ({} bytes)", DMA_LEN));
        }
        if result.is_err() {
            unsafe { slot_take(slot_idx, log) };
        }
        result
    }
}

fn fourcc(v: u32) -> [u8; 4] {
    [
        (v & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
    ]
}

unsafe extern "C" fn evt_prepare_hardware(
    device: wdf::WDFDEVICE,
    _resources_raw: wdf::WDFCMRESLIST,
    resources_translated: wdf::WDFCMRESLIST,
) -> u32 {
    let mut log = KernelLog::new();
    vlog(&mut log, format_args!("=== EvtDevicePrepareHardware (P1c-3 resource-list bring-up) ==="));

    let result = unsafe { Probe { log: &mut log }.run(device, resources_translated) };
    match &result {
        Ok(()) => vlog(
            &mut log,
            format_args!("=== probe OK: BARs mapped from ResourcesTranslated, FEATURES_OK, queues ready, OPEN answered ==="),
        ),
        Err(e) => vlog(&mut log, format_args!("=== probe FAILED: {} (0x{:?}) ===", e.text(), e)),
    }
    log.finish(device);

    match result {
        Ok(()) => STATUS::SUCCESS.to_u32(),
        // Make a failed bring-up visible in Device Manager (Code 10) instead of
        // pretending that a started-but-dead device is fine.
        Err(_) => STATUS::UNSUCCESSFUL.to_u32(),
    }
}

unsafe extern "C" fn evt_release_hardware(
    device: wdf::WDFDEVICE,
    _resources_translated: wdf::WDFCMRESLIST,
) -> u32 {
    // P1c-3: the BAR mappings created in EvtDevicePrepareHardware live until
    // here. DbgPrint only: do not overwrite the probe log in the registry.
    if let Some(idx) = unsafe { slot_lookup(device) } {
        let mut log = KernelLog::new();
        let n = unsafe { slot_take(idx, &mut log) };
        vlog(
            &mut log,
            format_args!("=== EvtDeviceReleaseHardware: released {} mapped memory BAR(s) ===", n),
        );
    }
    STATUS::SUCCESS.to_u32()
}

unsafe extern "C" fn evt_driver_device_add(_driver: wdf::WDFDRIVER, mut device_init: wdf::PWDFDEVICE_INIT) -> u32 {
    dbg_line(b"EvtDeviceAdd: claiming a virtio-media function (PCI 1AF4:1070)");

    let mut pnp: wdf::WDF_PNPPOWER_EVENT_CALLBACKS = zeroed();
    pnp.Size = size_of::<wdf::WDF_PNPPOWER_EVENT_CALLBACKS>() as u32;
    pnp.EvtDevicePrepareHardware = Some(evt_prepare_hardware);
    pnp.EvtDeviceReleaseHardware = Some(evt_release_hardware);
    wdf_device_init_set_pnp_callbacks(device_init, &mut pnp);

    let mut device: wdf::WDFDEVICE = ptr::null_mut();
    if let Err(status) = wdf_device_create(&mut device_init, &mut device, ptr::null_mut()) {
        dbg_line(b"WdfDeviceCreate failed");
        return status.to_u32();
    }

    set_friendly_name(device);

    // PCI identity as the PnP manager sees it (this is also what the INF matched).
    let mut buf = [0u8; 260];
    let n = query_ascii_property(device, wdf::DEVICE_REGISTRY_PROPERTY::DevicePropertyHardwareID, &mut buf);
    if n > 0 {
        let mut line = [0u8; 192];
        let mut k = 0;
        for &b in b"hardware id: ".iter().chain(buf[..n].iter()) {
            if k < line.len() - 1 {
                line[k] = b;
                k += 1;
            }
        }
        dbg_line(&line[..k]);
        let want = b"PCI\\VEN_1AF4&DEV_1070";
        let matches = buf[..n].len() >= want.len() && buf[..want.len()].eq_ignore_ascii_case(want);
        if matches {
            dbg_line(b"device id 0x1070 (VIRTIO_ID_MEDIA) matched");
        } else {
            dbg_line(b"WARNING: hardware id is not a virtio-media function");
        }
    } else {
        dbg_line(b"hardware id query failed");
    }

    STATUS::SUCCESS.to_u32()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn DriverEntry(driver: wdf::PDRIVER_OBJECT, registry_path: wdf::PCUNICODE_STRING) -> u32 {
    dbg_line(b"DriverEntry (virtio-media P1c-3, resource-list BAR mapping)");

    // Guards the per-device mapping slots (two virtio-media functions can start
    // back to back).
    unsafe { wdm::KeInitializeSpinLock(ptr::addr_of_mut!(SLOTS_LOCK)) };

    let mut config: wdf::WDF_DRIVER_CONFIG = zeroed();
    config.Size = size_of::<wdf::WDF_DRIVER_CONFIG>() as u32;
    config.EvtDriverDeviceAdd = Some(evt_driver_device_add);

    ntstatus(wdf::WdfDriverCreate(driver, registry_path, ptr::null_mut(), &mut config))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { wdm::KeBugCheck(0xDEAD_DEAD) }
}
