//! virtio-media Windows guest driver (KMDF, ARM64) - P1d decode-frame bring-up.
//!
//! P1c-3 brought the virtio 1.x transport up from `ResourcesTranslated` only:
//! common config, both queues, `OPEN`, `ENUM_FMT`. P1d keeps that session open
//! and drives one real H.264 IDR access unit through the host MediaCodec
//! decoder, then takes the decoded NV12 frame from the device's `media_host`
//! pool:
//!
//!   1. the ACPI `DRVM0001\MEDIA_HOST` device is bound too, and its memory
//!      resource gives the guest-physical base/size of the `media_host` pool;
//!   2. on the PCI function the driver does `OPEN`, `S_FMT(OUTPUT, H264)`,
//!      `S_FMT(CAPTURE, NV12)`, `REQBUFS(MMAP)`, `QUERYBUF`, `MMAP`, `QBUF`,
//!      `SUBSCRIBE_EVENT(SOURCE_CHANGE)`, `STREAMON`;
//!   3. it polls the eventq for `DQBUF(CAPTURE)`, writes the NV12 frame to
//!      `C:\DroidVM\p1d\frame.raw` and logs its geometry and Y-plane stats;
//!   4. the session is **not** closed and the device is left running; only
//!      `EvtDeviceReleaseHardware` resets it and frees the vrings/pool mapping.
//!
//! There is **no PCI config-space read or write anywhere** in this driver.
//!
//! P-BATCH MSI-X (1.0.0.17): both virtqueues now raise the function's MSI-X
//! message and the transport waits on an event instead of spinning on
//! `KeStallExecutionProcessor` (see `irq.rs`). The polling path is kept and is
//! what the queues use whenever no usable message interrupt was granted, so a
//! device that never delivers an interrupt behaves exactly like 1.0.0.16.
//!
//! The register/queue/protocol logic lives in `virtio_media.rs`; the platform
//! glue (resource list, mapping, layout probing, file dump) lives here.

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

use alloc::boxed::Box;
use alloc::vec::Vec;

use core::ffi::c_void;
use core::fmt::Write as _;
use core::mem::{size_of, transmute, zeroed};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use winresult::STATUS;
use wdk::wdf as wdf;
use wdk::wdm as wdm;

mod virtio_media;
mod encoder_abi;
mod encoder_state;
mod irq;
mod p1d;
mod vmedia_abi;

use p1d::map_pool;
use p1d::wait_pool;
use p1d::EventDma;
use p1d::LiveState;
use p1d::SessionConfig;
use p1d::SessionSlot;

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

/// DEVPKEY_Device_InstanceId -{78c34fc8-104a-4aca-9ea4-524d52996e57}, 256.
const DEVPKEY_DEVICE_INSTANCE_ID: wdm::DEVPROPKEY = wdm::DEVPROPKEY {
    fmtid: wdm::DEVPROPGUID {
        Data1: 0x78c3_4fc8,
        Data2: 0x104a,
        Data3: 0x4aca,
        Data4: [0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57],
    },
    pid: 256,
};

const FRIENDLY_NAME: &[u8] = b"DroidVM Video Media";
const POOL_DEVICE_NAME: &[u8] = b"DroidVM Media Pool";

/// Internal driver version, kept in sync with the INF `DriverVer` (P2-1).
/// 1.0.0.9 = P2-2f (session lifecycle: 16-byte CLOSE, close-before-reopen, MUNMAP).
/// 1.0.0.14 = VP9, 1.0.0.15 = HEVC, 1.0.0.16 = AV1.
/// 1.0.0.17 = P-BATCH MSI-X (interrupt-driven used ring, polling fallback).
/// 1.0.0.18 = P-BATCH ZEROCOPY (MAP_FRAME/RELEASE_FRAME).
/// 1.0.0.19 = MERGE-20261024: one tree for all eight P-BATCH patches, no new ABI.
/// 1.0.0.20 = P-BATCH POOLFIX (E173): capacity-based REQBUFS ask, rollback of a
/// failed configure (STREAMOFF + MUNMAP + REQBUFS(0)), AV1 in the OPEN log.
/// 1.0.0.21 = HEVC-MAIN10: VM_OPEN_CODEC_HEVC_MAIN10 (4) selects a HEVC Main10
/// session, whose CAPTURE queue is negotiated as V4L2_PIX_FMT_P010 (10-bit,
/// two-plane) with a logged NV12 fallback.  No IOCTL or struct-layout change.
/// 1.0.0.22 = CONCURRENT-MAPPING: the single-slot `mapped`/`mapped_process` pair
/// became a table indexed by capture buffer, so MAP_FRAME can hand out as many
/// buffers as REQBUFS granted (18..20 for 1080p) instead of refusing the second
/// one with err=22.  RELEASE_FRAME(index) frees exactly that index and
/// 0xFFFFFFFF still means "release all".  CLOSE/FLUSH/OPEN/teardown release the
/// whole table before the pool is unmapped.  No IOCTL or struct-layout change.
/// 1.0.0.23 = CACHED-POOL: the `media_host` pool (and the per-frame user window
/// `MAP_FRAME` builds over its pages) is mapped `MmCached` instead of
/// `MmNonCached`, with per-frame cache maintenance on both directions
/// (`dc ivac` before the guest reads a decoded frame, `dc civac` after the guest
/// writes an access unit).  This is a **memory-attribute** change only: same
/// IOCTL table, same struct layouts, same protocol.  A UMD does not have to know
/// -- but a pre-1.0.0.23 *driver* is what made `up` cost 28 ms, so the UMD logs
/// `DriverVersion` and this version is the one whose read is ~1 ms.
const DRIVER_VERSION: &str = "1.0.0.36";

/// HEVC-MAIN10 build stamp: the line an on-machine session can grep to tell this
/// build from 1.0.0.20 (`strings virtio_media.sys | grep MAIN10`), printed next
/// to the 1.0.0.18 ZEROCOPY stamp at device start.
const BUILD_STAMP: &str = "HEVC-MAIN10 build 1.0.0.21: VM_OPEN_CODEC_HEVC_MAIN10=4, S_FMT CAPTURE V4L2_PIX_FMT_P010 ('P010') with NV12 fallback";

/// CONCURRENT-MAPPING build stamp (1.0.0.22): one line on the machine that says
/// the per-buffer mapping table is live, so a log can never be read as if the
/// 1.0.0.21 single-slot behaviour were still running.
const BUILD_STAMP_CONCMAP: &str = "CONCURRENT-MAPPING build 1.0.0.22: one mapping per capture buffer (a second MAP_FRAME no longer answers err=22), RELEASE_FRAME(index) frees exactly that index, 0xFFFFFFFF = release all, CLOSE/FLUSH/OPEN/teardown release the whole table";

/// CACHED-POOL build stamp (1.0.0.23): says on the machine that the pool mapping
/// is `MmCached` + maintained per frame, so a 30 ms `up` can never be read as if
/// the 1.0.0.22 `MmNonCached` mapping were still in place.
const BUILD_STAMP_CACHED: &str = "CACHED-POOL build 1.0.0.23: media_host pool + MAP_FRAME user windows mapped MmCached (was MmNonCached), dc ivac over the frame window before the caller reads it, dc civac after an access unit is written into an OUTPUT buffer";

/// SESSION-OWNERSHIP build stamp (1.0.0.24): the line that says the machine is
/// running the driver where a CLOSE only closes *its own* session.  Without it,
/// a log that shows the old "OPEN: session N still open -> closing it" line can
/// be mistaken for this build.
const BUILD_STAMP_OWNERSHIP: &str = "SESSION-OWNERSHIP build 1.0.0.24: VM_OPEN_OUT.SessionToken generation + 2 session slots per function, CLOSE/FLUSH/SEND(EX)/GET_FRAME/MAP_FRAME/RELEASE_FRAME check the token (0 = legacy, accepted only while it is the only session), a replaced session's CLOSE is ignored not applied";

/// PER-SESSION-LIVESTATE build stamp (1.0.0.25): the line that says the event
/// queue is demultiplexed by the session the host names, so a completion for one
/// session is delivered to that session instead of being dropped by whichever
/// request happened to pump the queue.  Without this line on the machine, a
/// dual-session log can still be the 1.0.0.24 behaviour (`event for session N
/// (ours M) ignored` followed by `no free OUTPUT buffer after 4000 spins`).
const BUILD_STAMP_PERSESSION: &str = "PER-SESSION-LIVESTATE build 1.0.0.25: eventq completions are dispatched to the session the host names (token/slot), per-session ERROR latch, async QBUF errno carries its owner slot; a second session no longer starves the first one's OUTPUT buffers";
const BUILD_STAMP_TAG: &str = "TAG build 1.0.0.26: signed64 timeval tag OUTPUT->CAPTURE, strict event length/canonical validation, per-session capture tag state";

/// Sanity cap on the ACPI-announced `media_host` pool; a larger descriptor is
/// rejected instead of mapped.  96 MiB -- the size the fix wants -- is well
/// inside it, so a VMM that announces more (`--pre-alloc media-host-mb=96`) is
/// accepted without a driver change.  The pool *size* itself is the VMM's: the
/// driver maps exactly the `_CRS` range and cannot enlarge it (E173).
const POOL_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// E173 diagnostic: the pool size below which the 20-buffer ask no longer fits a
/// 1920x1152 NV12 frame.  Logged once at prepare time; the actual ask is derived
/// from the announced size, not from this number.
const POOL_TARGET_BYTES: u64 = 96 * 1024 * 1024;

// ---- NTSTATUS values used by the IOCTL handlers ---------------------------
// (Kept as u32 because WDFRequestComplete takes a raw NTSTATUS.)
const ST_SUCCESS: u32 = 0x0000_0000;
const ST_UNSUCCESSFUL: u32 = 0xC000_0001;
const ST_DATA_ERROR: u32 = 0xC000_003E;
const ST_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
const ST_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const ST_INVALID_DEVICE_STATE: u32 = 0xC000_0184;
const ST_DEVICE_NOT_READY: u32 = 0xC000_00A3;
const ST_IO_TIMEOUT: u32 = 0xC000_00B5;
const ST_NOT_SUPPORTED: u32 = 0xC000_00BB;
const ST_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const ST_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;

/// Guest-physical base/size of the `media_host` pool, announced by the ACPI
/// `DRVM0001\MEDIA_HOST` device and consumed by the PCI function.
static POOL_BASE: AtomicU64 = AtomicU64::new(0);
static POOL_SIZE: AtomicU64 = AtomicU64::new(0);

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
        Self { buf: Vec::with_capacity(32768) }
    }

    fn finish(&self, device: wdf::WDFDEVICE) {
        flush_registry_log(device, b"VirtioMediaLog", &self.buf);
    }
}

/// Write an ASCII log blob to the device's driver registry key as a Unicode
/// string.  Called once from PrepareHardware and on (throttled) IOCTL flushes.
/// `UNICODE_STRING.Length` is a USHORT, so a value holds at most ~32,000
/// characters: the first 30,000 bytes of the ring are what the registry shows.
fn flush_registry_log(device: wdf::WDFDEVICE, value_name: &[u8], bytes: &[u8]) {
    let len = bytes.len().min(30000);
    if len == 0 {
        return;
    }
    let mut utf16: Vec<u16> = Vec::with_capacity(len + 1);
    for &b in &bytes[..len] {
        utf16.push(b as u16);
    }
    utf16.push(0);
    let mut value = wdf::UNICODE_STRING {
        Length: ((utf16.len() - 1) * 2) as u16,
        MaximumLength: (utf16.len() * 2) as u16,
        Buffer: utf16.as_mut_ptr(),
    };
    let mut name_buf: Vec<u16> = Vec::with_capacity(value_name.len() + 1);
    for &b in value_name {
        name_buf.push(b as u16);
    }
    name_buf.push(0);
    let mut name = wdf::UNICODE_STRING {
        Length: ((name_buf.len() - 1) * 2) as u16,
        MaximumLength: (name_buf.len() * 2) as u16,
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

impl virtio_media::Log for KernelLog {
    fn line(&mut self, s: &str) {
        dbg_line(s.as_bytes());
        if self.buf.len() + s.len() + 2 <= 32768 {
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.extend_from_slice(b"\r\n");
        }
    }
}

// ---- IOCTL log ring -------------------------------------------------------
// One connection at a time is enough (the decoder's user-mode test), so a
// single ring is simpler than a Vec inside the locked session state.  It is
// flushed to `VirtioMediaIoctlLog` after an IOCTL.
//
// P3/1.0.0.10: the cap is 128 KiB (P2-2F had 16 KiB) because a streaming
// session logs one line per decoded frame and a 15 s playback is ~375 frames.
// When the buffer *is* full, the oldest line is dropped instead of the new one,
// so the tail -- including the CLOSE line with the AU/frame totals -- always
// survives.  Flushes are throttled to every 4 KiB of growth (and forced on
// OPEN/CLOSE): copying and rewriting the buffer on each of the IOCTLs per frame
// would put registry I/O in the middle of the decode path.
const IOLOG_CAP: usize = 131072;
static mut IOLOG_BUF: [u8; IOLOG_CAP] = [0; IOLOG_CAP];
static mut IOLOG_LEN: usize = 0;
static mut IOLOG_LOCK: wdm::KSPIN_LOCK = 0;
static LAST_FLUSH_LEN: AtomicUsize = AtomicUsize::new(0);
static IOCTL_TICK: AtomicUsize = AtomicUsize::new(0);

struct IoLog;

impl virtio_media::Log for IoLog {
    fn line(&mut self, s: &str) {
        io_log_line(s);
    }
}

fn io_log_reset() {
    unsafe {
        let irql = wdm::KeAcquireSpinLockRaiseToDpc(ptr::addr_of_mut!(IOLOG_LOCK));
        IOLOG_LEN = 0;
        wdm::KeReleaseSpinLock(ptr::addr_of_mut!(IOLOG_LOCK), irql);
    }
    LAST_FLUSH_LEN.store(0, Ordering::Relaxed);
}

fn io_log_line(s: &str) {
    dbg_line(s.as_bytes());
    unsafe {
        let irql = wdm::KeAcquireSpinLockRaiseToDpc(ptr::addr_of_mut!(IOLOG_LOCK));
        let buf = ptr::addr_of_mut!(IOLOG_BUF) as *mut u8;
        let mut len = IOLOG_LEN;
        let need = s.len() + 2;
        // Make room by dropping whole lines from the front (keep the tail).
        while len + need > IOLOG_CAP && len != 0 {
            let mut first = 0usize;
            while first + 1 < len {
                if *buf.add(first) == b'\r' && *buf.add(first + 1) == b'\n' {
                    break;
                }
                first += 1;
            }
            let drop = core::cmp::min(first + 2, len);
            ptr::copy(buf.add(drop), buf, len - drop);
            len -= drop;
        }
        if len + need <= IOLOG_CAP {
            ptr::copy_nonoverlapping(s.as_ptr(), buf.add(len), s.len());
            ptr::copy_nonoverlapping(b"\r\n".as_ptr(), buf.add(len + s.len()), 2);
            IOLOG_LEN = len + need;
        }
        wdm::KeReleaseSpinLock(ptr::addr_of_mut!(IOLOG_LOCK), irql);
    }
}

fn io_log_flush(device: wdf::WDFDEVICE, force: bool) {
    let mut copy: Vec<u8> = Vec::with_capacity(IOLOG_CAP);
    unsafe {
        let irql = wdm::KeAcquireSpinLockRaiseToDpc(ptr::addr_of_mut!(IOLOG_LOCK));
        let len = IOLOG_LEN;
        if !force {
            let last = LAST_FLUSH_LEN.load(Ordering::Relaxed);
            if len <= last || len - last < 4096 {
                wdm::KeReleaseSpinLock(ptr::addr_of_mut!(IOLOG_LOCK), irql);
                return;
            }
        }
        copy.resize(len, 0);
        let buf = ptr::addr_of_mut!(IOLOG_BUF) as *const u8;
        copy.copy_from_slice(core::slice::from_raw_parts(buf, len));
        wdm::KeReleaseSpinLock(ptr::addr_of_mut!(IOLOG_LOCK), irql);
    }
    LAST_FLUSH_LEN.store(copy.len(), Ordering::Relaxed);
    flush_registry_log(device, b"VirtioMediaIoctlLog", &copy);
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

unsafe fn request_file_object(request:wdf::WDFREQUEST)->wdf::WDFFILEOBJECT {
    let Some(pfn)=wdf_table_fn!(wdf::PFN_WDFREQUESTGETFILEOBJECT,WdfRequestGetFileObjectTableIndex) else{return ptr::null_mut()};
    pfn(wdf::WdfDriverGlobals,request)
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

fn ascii_starts_with(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay[..needle.len()].eq_ignore_ascii_case(needle)
}

fn ascii_ends_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay[hay.len() - needle.len()..].eq_ignore_ascii_case(needle)
}

/// Does the `card` name contain `needle`? P1c-3 saw "droidvm decoder" and
/// "droidvm encoder" in the device config; P1d only drives the decoder.
fn card_contains(card: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || card.len() < needle.len() {
        return false;
    }
    for i in 0..=card.len() - needle.len() {
        if card[i..i + needle.len()].eq_ignore_ascii_case(needle) {
            return true;
        }
    }
    false
}

/// Read `DEVPKEY_Device_InstanceId` from the PDO. The ACPI pools share the
/// `ACPI\DRVM0001` hardware id, so the instance id (`...\MEDIA_HOST`) is what
/// tells the media pool apart from the GPU/Venus pools.
unsafe fn query_instance_id(device: wdf::WDFDEVICE, out: &mut [u8; 260]) -> usize {
    let pdo = wdf_device_wdm_get_physical_device(device);
    if pdo.is_null() {
        return 0;
    }
    let mut utf16 = [0u16; 260];
    let mut len: u32 = 0;
    let mut typ: u32 = 0;
    let raw = wdm::IoGetDevicePropertyData(
        pdo,
        &DEVPKEY_DEVICE_INSTANCE_ID,
        0,
        0,
        (utf16.len() * 2) as u32,
        utf16.as_mut_ptr() as *mut core::ffi::c_void,
        &mut len,
        &mut typ,
    );
    if !winresult::NtStatus::from(raw).is_success() {
        return 0;
    }
    if typ != DEVPROP_TYPE_STRING {
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

/// The ACPI `MEDIA_HOST` device's `_CRS` is the `media_host` pool: one memory
/// descriptor with its guest-physical base and size.
unsafe fn prepare_pool(
    resources: wdf::WDFCMRESLIST,
    log: &mut dyn virtio_media::Log,
) -> Result<(), virtio_media::Error> {
    let Some(get_count) = wdf_table_fn!(
        wdf::PFN_WDFCMRESOURCELISTGETCOUNT,
        WdfCmResourceListGetCountTableIndex
    ) else {
        return Err(virtio_media::Error::NoMemoryResources);
    };
    let Some(get_desc) = wdf_table_fn!(
        wdf::PFN_WDFCMRESOURCELISTGETDESCRIPTOR,
        WdfCmResourceListGetDescriptorTableIndex
    ) else {
        return Err(virtio_media::Error::NoMemoryResources);
    };
    let n = get_count(wdf::WdfDriverGlobals, resources);
    vlog(log, format_args!("ACPI MEDIA_HOST: translated list count={}", n));
    for i in 0..n {
        let desc = get_desc(wdf::WdfDriverGlobals, resources, i);
        if desc.is_null() {
            continue;
        }
        let typ = unsafe { (*desc).Type as u32 };
        let flags = unsafe { (*desc).Flags as u32 };
        let (start, len) = match typ {
            wdm::CmResourceTypeMemory => (
                unsafe { (*desc).u.Memory.Start.QuadPart as u64 },
                unsafe { (*desc).u.Memory.Length as u64 },
            ),
            7 => {
                if flags & 0x0800 != 0 {
                    (
                        unsafe { (*desc).u.Memory64.Start.QuadPart as u64 },
                        unsafe { (*desc).u.Memory64.Length64 as u64 },
                    )
                } else if flags & 0x0400 != 0 {
                    (
                        unsafe { (*desc).u.Memory48.Start.QuadPart as u64 },
                        unsafe { (*desc).u.Memory48.Length48 as u64 },
                    )
                } else {
                    (
                        unsafe { (*desc).u.Memory40.Start.QuadPart as u64 },
                        unsafe { (*desc).u.Memory40.Length40 as u64 },
                    )
                }
            }
            _ => {
                vlog(log, format_args!("ACPI res[{}] type={} (not memory, skipped)", i, typ));
                continue;
            }
        };
        vlog(
            log,
            format_args!(
                "ACPI res[{}] memory pa=0x{:X} len=0x{:X} flags=0x{:04X}",
                i, start, len, flags
            ),
        );
        if start == 0 || len == 0 {
            continue;
        }
        if len > POOL_MAX_BYTES {
            vlog(log, format_args!("ACPI pool len 0x{:X} exceeds sanity limit", len));
            continue;
        }
        POOL_BASE.store(start, Ordering::SeqCst);
        POOL_SIZE.store(len, Ordering::SeqCst);
        vlog(
            log,
            format_args!("media_host pool announced: base=0x{:X} size=0x{:X} ({} MiB)", start, len, len >> 20),
        );
        // E173: the pool is the VMM's, not the driver's -- it is the `_CRS`
        // memory descriptor crosvm creates for `--pre-alloc media-host-mb=N`.
        // Say out loud which side of the 96 MiB target this boot is on, so a
        // "REQBUFS asked 18 instead of 20" line has its reason next to it.
        if len < POOL_TARGET_BYTES {
            vlog(
                log,
                format_args!(
                    "media_host pool {} MiB < {} MiB target: 1920x1152 frames need ~69.7 MiB for 20; the driver asks capacity-2 instead (raise the VMM's --pre-alloc media-host-mb to 96 for full depth)",
                    len >> 20,
                    POOL_TARGET_BYTES >> 20
                ),
            );
        } else {
            vlog(
                log,
                format_args!(
                    "media_host pool {} MiB >= {} MiB target: the full {}-buffer ask fits even at 1920x1152",
                    len >> 20,
                    POOL_TARGET_BYTES >> 20,
                    p1d::CAPTURE_BUFS
                ),
            );
        }
    }
    if POOL_BASE.load(Ordering::SeqCst) == 0 {
        return Err(virtio_media::Error::PoolMissing);
    }
    Ok(())
}



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
    /// P1d: the live session (vrings, event buffers, device pointers, pool
    /// mapping) kept open after a successful decode. Owned by `Box`.
    live: *mut LiveState,
}

const EMPTY_SLOT: DevSlot = DevSlot {
    device: ptr::null_mut(),
    bars: [EMPTY_BAR; MAX_MAPPED_BARS],
    count: 0,
    live: ptr::null_mut(),
};

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
    let live;
    let irql = unsafe { slots_lock() };
    {
        let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
        let slot = unsafe { &mut *slots.add(idx) };
        count = slot.count;
        copy[..count].copy_from_slice(&slot.bars[..count]);
        live = slot.live;
        *slot = EMPTY_SLOT;
    }
    unsafe { slots_unlock(irql) };

    // Drop the live session first: it resets the device (so the host stops
    // touching the vrings/pool) and unmaps the pool while the BARs are valid.
    if !live.is_null() {
        vlog(log, format_args!("release live virtio-media session (reset + free vrings + pool)"));
        unsafe { drop(Box::from_raw(live)) };
    }

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
///
/// `wdf_device` identifies the device object, which is the key the MSI-X
/// interrupt state is stored under: the transport wait loops pass it to
/// `irq::wait(mmio.wdf_device)` (P-BATCH MSI-X).
struct Kmmio {
    common: *mut u8,
    notify: *mut u8,
    device: *mut u8,
    wdf_device: wdf::WDFDEVICE,
    events: Option<Box<p1d::DeviceEvents>>,
}

impl Kmmio {
    fn harvest_events(&mut self) -> Result<(), virtio_media::Error> {
        let Some(mut events) = self.events.take() else { return Ok(()); };
        // Move the unique owner out temporarily; no alias of mmio or session
        // storage, and harvest has no command/callback/error-unwind operations.
        events.harvest(self);
        let failed = events.poisoned;
        self.events = Some(events);
        if failed { Err(virtio_media::Error::DeviceStatus(0xFF)) } else { Ok(()) }
    }
    fn poisoned(&self) -> bool { self.events.as_ref().is_some_and(|e| e.poisoned) }
}

impl virtio_media::Mmio for Kmmio {
    fn progress_events(&mut self) -> Result<(), virtio_media::Error> { self.harvest_events() }
    fn transport_poison(&mut self) { if let Some(e) = self.events.as_mut() { e.poisoned = true; } }
    fn transport_failed(&self) -> bool { self.poisoned() }

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
/// Start of the fire-and-forget command slots: right after RESP_OFF+RESP_CAP,
/// with 32768 - 18432 = 14336 bytes to spare (4 slots x 1536 B = 6144 B).
const ASYNC_BASE: usize = 18432;
/// Bytes per async slot: one REQ_CAP request followed by one RESP_CAP response.
const ASYNC_STRIDE: usize = REQ_CAP + RESP_CAP;

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
        resources_raw: wdf::WDFCMRESLIST,
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
            wdf_device: device,
            events: None,
        };
        let mut dma_holder: Option<Dma> = None;
        let mut evt_holder: Option<EventDma> = None;
        let mut pool_out: Option<(*mut u8, u64)> = None;
        let mut q0_out: Option<virtio_media::Queue> = None;
        

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

            // ---- P-BATCH MSI-X: the interrupt object ---------------------
            // Created here (not in EvtDeviceAdd) because this is the only place
            // WDF accepts the raw/translated interrupt descriptors, and it is
            // still PASSIVE_LEVEL and before the framework enables interrupts.
            let isr_va = match caps.isr {
                Some(r) => unsafe { bar.va.add(r.offset as usize) },
                None => ptr::null_mut(),
            };
            let num_queues = virtio_media::num_queues(&mmio);
            let msix =
                unsafe { irq::install(device, isr_va, num_queues, resources_raw, resources, log) };
            vlog(
                log,
                format_args!(
                    "irq: queue_msix_vector <- 0x{:04X} ({}, interrupt object {})",
                    msix.vector,
                    if msix.vector == irq::NO_VECTOR { "polled" } else { "interrupt" },
                    if msix.installed { "armed" } else { "absent" }
                ),
            );

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
                msix.vector,
                "commandq",
                log,
            )?;
            // P3-6 / 1.0.0.12: give commandq its fire-and-forget slots. Each slot
            // has its own request (512 B) and response (1024 B) DMA so a QBUF the
            // device has not picked up yet can never be overwritten, and the
            // descriptor chain of slot i is at 2 + 2*i (0/1 stay the sync chain).
            {
                let mut areq = [virtio_media::Buf::empty(); virtio_media::ASYNC_SLOTS];
                let mut aresp = [virtio_media::Buf::empty(); virtio_media::ASYNC_SLOTS];
                for i in 0..virtio_media::ASYNC_SLOTS {
                    let off = ASYNC_BASE + i * ASYNC_STRIDE;
                    areq[i] = virtio_media::Buf {
                        va: unsafe { dma.va.add(off) },
                        pa: dma.pa + off as u64,
                        len: REQ_CAP,
                    };
                    aresp[i] = virtio_media::Buf {
                        va: unsafe { dma.va.add(off + REQ_CAP) },
                        pa: dma.pa + (off + REQ_CAP) as u64,
                        len: RESP_CAP,
                    };
                }
                virtio_media::set_async_slots(&mut q0, areq, aresp);
                vlog(
                    log,
                    format_args!(
                        "commandq async slots: {} x ({} req + {} resp) at dma+0x{:X}, desc 2..{}",
                        virtio_media::ASYNC_SLOTS,
                        REQ_CAP,
                        RESP_CAP,
                        ASYNC_BASE,
                        1 + 2 * virtio_media::ASYNC_SLOTS
                    ),
                );
            }
            let mut q1 = virtio_media::setup_queue(
                &mut mmio,
                virtio_media::QUEUE_EVENT,
                q1mem,
                virtio_media::QUEUE_DEPTH,
                caps.notify_off_multiplier,
                msix.vector,
                "eventq",
                log,
            )?;
            virtio_media::driver_ok(&mut mmio, log)?;

            // ---- device config -------------------------------------------
            if caps.device.is_none() {
                vlog(log, format_args!("device config capability is missing"));
                return Err(virtio_media::Error::MissingRegion("device"));
            }
            let mcfg = virtio_media::read_media_config(&mmio, log)?;

            // ---- P2-1: transport only; the user-mode client owns the session
            // The P1d-2 decode sequence now lives in p1d::configure_and_send /
            // p1d::take_frame, driven by the IOCTLs below.  The device is left
            // idle (no OPEN, no H.264 blob, no frame.raw write) until a client
            // asks for it.
            let is_decoder = card_contains(&mcfg.card, b"decoder");
            let is_encoder = card_contains(&mcfg.card, b"encoder");
            let mut pool_base_out = 0u64;
            let (pool_va, pool_size) = if is_decoder || is_encoder {
                let (pool_base, size) = wait_pool(log).ok_or(virtio_media::Error::PoolMissing)?;
                pool_base_out = pool_base;
                vlog(
                    log,
                    format_args!(
                        "media_host pool: base=0x{:X} size=0x{:X} ({} MiB)",
                        pool_base, size, size >> 20
                    ),
                );
                let va = unsafe { map_pool(pool_base, size, log) }
                    .ok_or(virtio_media::Error::PoolMissing)?;
                pool_out = Some((va, size));
                (va, size as usize)
            } else {
                (ptr::null_mut(), 0usize)
            };

            let link = if is_decoder {
                Some(vmedia_abi::VMEDIA_LINK_DECODER)
            } else if is_encoder {
                Some(vmedia_abi::VMEDIA_LINK_ENCODER)
            } else {
                None
            };
            if let Some(link) = link {
                unsafe { create_symbolic_link(device, link, log) };
            }

            let events = p1d::DeviceEvents::try_allocate()
                .ok_or(virtio_media::Error::NoMemoryResources)?;
            let evt = evt_holder.insert(
                unsafe { EventDma::alloc(log) }
                    .ok_or(virtio_media::Error::QueueMemorySmall(0, 8 * virtio_media::EVENT_CAP))?,
            );
            // The allocated FIFO is uninitialized but owns no resources yet.
            // All operations through publication below are infallible.
            for i in 0..virtio_media::EVENT_COUNT {
                virtio_media::post_event(&mut mmio, &mut q1, &evt.buf(i), i);
            }
            mmio.events = Some(unsafe {
                p1d::DeviceEvents::initialize(events, q1, evt_holder.take().unwrap_unchecked())
            });

            // Allocate before moving any owned transport resource. On OOM the
            // existing Err arm resets hardware, unmaps the pool, drops DMA/BARs.
            let live = LiveState::try_allocate()
                .ok_or(virtio_media::Error::NoMemoryResources)?;
            q0_out = Some(q0);
            Ok(Some((live, mcfg, pool_va, pool_size, is_decoder, pool_base_out)))
        })();

        match result {
            Ok(Some((mut live, mcfg, pool_va, pool_size, is_decoder, pool_base_out))) => {
                // Every operation from the first owned-resource write through
                // assume_init is infallible. Holders are Some by construction
                // of this Ok arm; no unwrap/callback/allocation after transfer.
                let dst = live.as_mut_ptr();
                unsafe {
                    LiveState::init_metadata_at(dst, is_decoder, mcfg.device_caps,
                        mcfg.device_type, mcfg.card);
                    let io = ptr::addr_of_mut!((*dst).io);
                    ptr::addr_of_mut!((*io).dma).write(dma_holder.take().unwrap_unchecked());
                    ptr::addr_of_mut!((*io).q0).write(q0_out.take().unwrap_unchecked());
                    ptr::addr_of_mut!((*io).mmio).write(mmio);
                    ptr::addr_of_mut!((*io).pool_va).write(pool_va);
                    ptr::addr_of_mut!((*io).pool_len).write(pool_size);
                    ptr::addr_of_mut!((*io).pool_pa).write(pool_base_out);
                    let slots = ptr::addr_of_mut!(SLOTS) as *mut DevSlot;
                    (*slots.add(slot_idx)).live = Box::into_raw(live.assume_init());
                }

                // Start a fresh IOCTL log for this device instance.
                io_log_reset();
                io_log_line(if is_decoder {
                    "=== device ready (decoder): IOCTL OPEN/SEND/GET_FRAME/CLOSE [P3] ==="
                } else {
                    "=== device ready (encoder): OPEN/CLOSE host owner; CONFIG/FRAME/PACKET not connected ==="
                });
                // NOTE: the ring is IOLOG_CAP (128 KiB) and the registry value
                // shows its first 30,000 bytes (UNICODE_STRING limit); the string
                // below said "64 KiB" when the cap was raised, kept as-is so it
                // matches the on-device build byte for byte.
                io_log_line("P-BATCH MSIX build 1.0.0.17: MSI-X used-ring interrupts (queue_msix_vector) + event wait, polling fallback kept; async per-AU QBUF, HEVC/VP9/AV1 codec selectors");
                // MERGE-20261024: one stamp that names the consolidated build, so
                // an on-device log says which tree is running without diffing
                // hashes.  The two lines below keep their own batch history.
                io_log_line("MERGE-20261024 build 1.0.0.19: one tree = VP9+HEVC+AV1 (single VM_OPEN_IN.Codec 0..3) + MSI-X + P010 + D3D12 DECODER_HEAP_SIZE + MAP_FRAME/RELEASE_FRAME");
                // P-BATCH POOLFIX (E173): the three behaviour changes of 1.0.0.20,
                // named here so the on-device ring says what it is running.
                io_log_line("P-BATCH POOLFIX build 1.0.0.20: REQBUFS ask = min(32 CAP32, pool/sizeimage - 2) >= 2; failed configure rolls back (STREAMOFF + MUNMAP + REQBUFS(0)); OPEN logs AV1 as AV1");
                // P-BATCH ZEROCOPY: says whether the direct-mapped frame path can
                // even be offered (`pa=0` means the ACPI pool base was never
                // announced, so MAP_FRAME answers PoolMissing and the UMD stays
                // on the staged path).
                let mut zc = virtio_media::LineBuf::new();
                let _ = write!(
                    zc,
                    "P-BATCH ZEROCOPY build 1.0.0.18: VM_IOCTL_MAP_FRAME/RELEASE_FRAME (pool pa=0x{:X} len=0x{:X}) -- direct NV12 read, staged GET_FRAME kept as fallback",
                    pool_base_out, pool_size
                );
                io_log_line(zc.as_str());
                // HEVC-MAIN10: one line that names this build on the machine and
                // what it added, so a session that "still looks 8-bit" can be
                // told from a session that runs the old binary immediately.
                io_log_line(BUILD_STAMP);
                io_log_line(BUILD_STAMP_CONCMAP);
                // CACHED-POOL: the line that says the pool mapping is cached and
                // maintained, and (immediately after it) what map_pool actually
                // got, because the fallback to MmNonCached is silent otherwise.
                io_log_line(BUILD_STAMP_CACHED);
                // SESSION-OWNERSHIP (1.0.0.24): the identity/generation line.  It
                // also carries the two facts a reader needs to interpret every
                // later log: how many slots exist, and that a zero token is the
                // legacy path.
                io_log_line(BUILD_STAMP_OWNERSHIP);
                // PER-SESSION-LIVESTATE (1.0.0.25): the line that says completions
                // are dispatched by the session the host names.  It is the only
                // on-machine way to tell this build from 1.0.0.24, whose pump
                // dropped the other session's events.
                io_log_line(BUILD_STAMP_PERSESSION);
                io_log_line(BUILD_STAMP_TAG);
                {
                    let mut c = virtio_media::LineBuf::new();
                    let _ = write!(
                        c,
                        "SESSION-OWNERSHIP: {} session slot(s), generation tokens from 0x{:08X}, token 0 = legacy client",
                        p1d::VMEDIA_MAX_SESSIONS,
                        vmedia_abi::VMEDIA_SESSION_OWNERSHIP_MIN_VERSION
                    );
                    io_log_line(c.as_str());
                }
                {
                    let mut c = virtio_media::LineBuf::new();
                    let _ = write!(
                        c,
                        "CACHED-POOL: pool mapping is {} (dc cache line = {} B)",
                        if p1d::POOL_CACHED.load(Ordering::SeqCst) {
                            "MmCached"
                        } else {
                            "MmNonCached -- cached mapping was refused, reads stay slow"
                        },
                        p1d::data_cache_line_bytes()
                    );
                    io_log_line(c.as_str());
                }
                // P-BATCH MSI-X: what the interrupt path ended up as. This is the
                // first thing to read on a machine: `vector=0x0000 irqs=...`
                // means MSI-X is live, `vector=0xFFFF` means the driver is
                // polling exactly like 1.0.0.16.
                irq::log_summary(device, "ready");
                io_log_flush(device, true);
                vlog(
                    log,
                    format_args!(
                        "=== device ready: {} {}; user-mode vmedia_client drives the session ===",
                        if is_decoder { "decoder" } else { "encoder" },
                        DRIVER_VERSION
                    ),
                );
                Ok(())
            }
            Ok(None) => {
                // Defensive: every virtio-media function now stores a live
                // transport for the IOCTL session, so this cannot happen.
                vlog(log, format_args!("=== device started without an IOCTL session ==="));
                Ok(())
            }
            Err(e) => {
                // A failure: quiesce the device before freeing anything, and
                // do not keep a live session.
                if !mmio.common.is_null() {
                    let st = virtio_media::status(&mut mmio);
                    virtio_media::set_status(&mut mmio, 0);
                    vlog(
                        log,
                        format_args!("reset: status 0x{:02X} -> 0x{:02X}", st, virtio_media::status(&mut mmio)),
                    );
                }
                if let Some((va, size)) = pool_out.take() {
                    unsafe { wdm::MmUnmapIoSpace(va as *mut c_void, size) };
                    vlog(log, format_args!("unmap media_host pool va=0x{:X} len=0x{:X}", va as usize, size));
                }
                if dma_holder.take().is_some() {
                    vlog(log, format_args!("free dma ({} bytes)", DMA_LEN));
                }
                if evt_holder.take().is_some() {
                    vlog(log, format_args!("free event dma ({} bytes)", 8 * virtio_media::EVENT_CAP));
                }
                unsafe { slot_take(slot_idx, log) };
                Err(e)
            }
        }
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

// ===========================================================================
// P2-1: WDF device interface, symbolic link, sequential IOCTL queue
// ===========================================================================

const _: () = assert!(size_of::<vmedia_abi::Guid>() == size_of::<wdf::GUID>());
const _: () = assert!(size_of::<vmedia_abi::VM_FRAME_INFO>() == 32);

unsafe fn create_device_interface(device: wdf::WDFDEVICE) -> u32 {
    let Some(pfn) = wdf_table_fn!(
        wdf::PFN_WDFDEVICECREATEDEVICEINTERFACE,
        WdfDeviceCreateDeviceInterfaceTableIndex
    ) else {
        return ST_INVALID_DEVICE_REQUEST;
    };
    let guid = vmedia_abi::VMEDIA_INTERFACE_GUID;
    let raw = pfn(
        wdf::WdfDriverGlobals,
        device,
        &guid as *const _ as *const wdf::GUID,
        ptr::null(),
    );
    if raw == ST_SUCCESS {
        dbg_line(b"device interface {A3B2C1D0-7E4A-4C1B-9F2D-6A5B8C7D9E01} created");
    } else {
        dbg_line(b"WdfDeviceCreateDeviceInterface failed (symbolic link is still created)");
    }
    raw
}

unsafe fn create_symbolic_link(device: wdf::WDFDEVICE, link: &[u8], log: &mut dyn virtio_media::Log) {
    let Some(pfn) = wdf_table_fn!(
        wdf::PFN_WDFDEVICECREATESYMBOLICLINK,
        WdfDeviceCreateSymbolicLinkTableIndex
    ) else {
        vlog(log, format_args!("WdfDeviceCreateSymbolicLink unavailable"));
        return;
    };
    let mut buf = [0u16; 64];
    let mut n = 0usize;
    for &b in link {
        if n + 1 >= buf.len() {
            break;
        }
        buf[n] = b as u16;
        n += 1;
    }
    buf[n] = 0;
    let name = wdf::UNICODE_STRING {
        Length: (n * 2) as u16,
        MaximumLength: ((n + 1) * 2) as u16,
        Buffer: buf.as_mut_ptr(),
    };
    let raw = pfn(wdf::WdfDriverGlobals, device, &name);
    let mut text = virtio_media::LineBuf::new();
    let _ = write!(text, "symbolic link ");
    for &b in &link[..link.len().min(60)] {
        let _ = write!(text, "{}", b as char);
    }
    if raw == ST_SUCCESS {
        vlog(log, format_args!("{} created", text.as_str()));
    } else if raw == ST_OBJECT_NAME_COLLISION {
        vlog(log, format_args!("{} already exists", text.as_str()));
    } else {
        vlog(log, format_args!("{} failed: NTSTATUS=0x{:08X}", text.as_str(), raw));
    }
}

unsafe fn create_io_queue(device: wdf::WDFDEVICE) -> u32 {
    let Some(pfn) = wdf_table_fn!(wdf::PFN_WDFIOQUEUECREATE, WdfIoQueueCreateTableIndex) else {
        return ST_INVALID_DEVICE_REQUEST;
    };
    let mut config: wdf::WDF_IO_QUEUE_CONFIG = zeroed();
    config.Size = size_of::<wdf::WDF_IO_QUEUE_CONFIG>() as u32;
    config.DispatchType = wdf::WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential;
    config.PowerManaged = wdf::WDF_TRI_STATE::WdfUseDefault;
    config.DefaultQueue = 1;
    config.EvtIoDeviceControl = Some(evt_io_device_control);
    let mut queue: wdf::WDFQUEUE = ptr::null_mut();
    let raw = pfn(wdf::WdfDriverGlobals, device, &mut config, ptr::null_mut(), &mut queue);
    if raw == ST_SUCCESS {
        dbg_line(b"sequential IOCTL queue created");
    } else {
        dbg_line(b"WdfIoQueueCreate failed");
    }
    raw
}

unsafe fn wdf_io_queue_get_device(queue: wdf::WDFQUEUE) -> wdf::WDFDEVICE {
    let Some(pfn) = wdf_table_fn!(wdf::PFN_WDFIOQUEUEGETDEVICE, WdfIoQueueGetDeviceTableIndex) else {
        return ptr::null_mut();
    };
    pfn(wdf::WdfDriverGlobals, queue)
}

unsafe fn wdf_request_complete(request: wdf::WDFREQUEST, status: u32, information: usize) {
    let Some(pfn) = wdf_table_fn!(
        wdf::PFN_WDFREQUESTCOMPLETEWITHINFORMATION,
        WdfRequestCompleteWithInformationTableIndex
    ) else {
        return;
    };
    pfn(wdf::WdfDriverGlobals, request, status, information as u64);
}

unsafe fn request_input(request: wdf::WDFREQUEST, min: usize) -> Result<(*mut u8, usize), u32> {
    let Some(pfn) = wdf_table_fn!(
        wdf::PFN_WDFREQUESTRETRIEVEINPUTBUFFER,
        WdfRequestRetrieveInputBufferTableIndex
    ) else {
        return Err(ST_INVALID_DEVICE_REQUEST);
    };
    let mut buffer: *mut c_void = ptr::null_mut();
    let mut length: usize = 0;
    let raw = pfn(wdf::WdfDriverGlobals, request, min, &mut buffer, &mut length);
    if winresult::NtStatus::from(raw).is_success() {
        Ok((buffer as *mut u8, length))
    } else {
        Err(raw)
    }
}

unsafe fn request_output(request: wdf::WDFREQUEST, min: usize) -> Result<(*mut u8, usize), u32> {
    let Some(pfn) = wdf_table_fn!(
        wdf::PFN_WDFREQUESTRETRIEVEOUTPUTBUFFER,
        WdfRequestRetrieveOutputBufferTableIndex
    ) else {
        return Err(ST_INVALID_DEVICE_REQUEST);
    };
    let mut buffer: *mut c_void = ptr::null_mut();
    let mut length: usize = 0;
    let raw = pfn(wdf::WdfDriverGlobals, request, min, &mut buffer, &mut length);
    if winresult::NtStatus::from(raw).is_success() {
        Ok((buffer as *mut u8, length))
    } else {
        Err(raw)
    }
}

/// Map a `libc` errno to the NTSTATUS the IOCTL completes with.
///
/// 1.0.0.11 matched `-errno` while `submit_req` stores the host's errno
/// **positive** (`i32::from_le_bytes` of the response header), so `-errno` was
/// always a negative number, never matched 12/22/38/110 and every error came out
/// as `STATUS_UNSUCCESSFUL` (0xC0000001).  That is why an exhausted media_host
/// pool (`REQBUFS` -> ENOMEM) showed up in the UMD as `err=31`
/// (ERROR_GEN_FAILURE) instead of `err=8` (ERROR_NOT_ENOUGH_MEMORY), and why
/// E147 could not tell a full pool from a broken session.  Accept both signs.
fn errno_status(errno: i32) -> u32 {
    let e = if errno < 0 { -errno } else { errno };
    match e {
        12 => ST_INSUFFICIENT_RESOURCES, // ENOMEM
        22 => ST_INVALID_PARAMETER,      // EINVAL
        38 | 95 => ST_NOT_SUPPORTED,     // ENOSYS / EOPNOTSUPP
        110 => ST_IO_TIMEOUT,            // ETIMEDOUT
        _ => ST_UNSUCCESSFUL,
    }
}

fn map_error(e: virtio_media::Error) -> u32 {
    let status = match e {
        virtio_media::Error::Errno(errno) | virtio_media::Error::IoctlFailed(_, errno) => {
            errno_status(errno)
        }
        virtio_media::Error::EventTimeout(_) | virtio_media::Error::ResponseTimeout(_, _, _) => {
            ST_IO_TIMEOUT
        }
        virtio_media::Error::PoolMissing => ST_DEVICE_NOT_READY,
        virtio_media::Error::ShortFrame(_, _)
        | virtio_media::Error::QueueMemorySmall(_, _)
        | virtio_media::Error::BitstreamTooLarge(_, _) => ST_BUFFER_TOO_SMALL,
        _ => ST_UNSUCCESSFUL,
    };
    let mut line = virtio_media::LineBuf::new();
    let _ = write!(line, "ioctl failed: {} (0x{:?}) -> NTSTATUS 0x{:08X}", e.text(), e, status);
    io_log_line(line.as_str());
    status
}

/// SESSION-OWNERSHIP (1.0.0.24): read the `(token, host_hint)` a request
/// carries.  Both are optional: a pre-1.0.0.24 client sends the short struct, so
/// the fields are simply not there and read as 0 -- which is exactly the legacy
/// encoding (`VMEDIA_NO_SESSION_TOKEN`).
unsafe fn session_hints(
    request: wdf::WDFREQUEST,
    token_off: Option<usize>,
    hint_off: Option<usize>,
) -> (u32, u32) {
    let (inp, got) = match unsafe { request_input(request, 0) } {
        Ok(v) => v,
        Err(_) => return (0, 0),
    };
    if inp.is_null() || got < 4 {
        return (0, 0);
    }
    let buf = unsafe { core::slice::from_raw_parts(inp, got) };
    let read = |off: usize| -> u32 {
        if off + 4 <= got {
            virtio_media::read_u32(buf, off)
        } else {
            0
        }
    };
    (
        token_off.map(read).unwrap_or(0),
        hint_off.map(read).unwrap_or(0),
    )
}

/// SESSION-OWNERSHIP: where the identity of a request lives in its input struct.
/// `(token offset, host-id offset)`, `None` where the field does not exist.
fn session_hint_offsets(code: u32) -> (Option<usize>, Option<usize>) {
    match code {
        // { SessionId, Flags, SessionToken, Reserved0 }
        vmedia_abi::VM_IOCTL_CLOSE | vmedia_abi::VM_IOCTL_FLUSH => (Some(8), Some(0)),
        // { SessionId, Index, SessionToken, Reserved0 }
        vmedia_abi::VM_IOCTL_RELEASE_FRAME => (Some(8), Some(0)),
        // { TimeoutMs, Flags, SessionToken, Reserved0 }
        vmedia_abi::VM_IOCTL_GET_FRAME | vmedia_abi::VM_IOCTL_MAP_FRAME | vmedia_abi::VM_IOCTL_GET_FRAME_TAG | vmedia_abi::VM_IOCTL_MAP_FRAME_TAG => (Some(8), None),
        // VM_SEND_IN_EX { Width, Height, Size, Flags, SessionToken, Reserved0 }
        vmedia_abi::VM_IOCTL_SEND_BITSTREAM_EX | vmedia_abi::VM_IOCTL_SEND_BITSTREAM_TAG => (Some(16), None),
        vmedia_abi::VM_IOCTL_ENC_CONFIG | vmedia_abi::VM_IOCTL_ENC_QUEUE_INPUT |
        vmedia_abi::VM_IOCTL_ENC_GET_PACKET | vmedia_abi::VM_IOCTL_ENC_DRAIN |
        vmedia_abi::VM_IOCTL_ENC_FLUSH => (Some(8), None),
        _ => (None, None),
    }
}

/// SESSION-OWNERSHIP: what one ownership decision lets the handler do.
enum Claim {
    /// The slot this request owns.
    Slot(usize),
    /// Refused; the handler returns this NTSTATUS and changes nothing.
    Refuse(u32),
}

/// Turn an [`p1d::Owner`] into a slot or a refusal, and log the decision.
///
/// `what` names the operation for the log.  A **legacy** request (no token, one
/// session) is allowed and counted; a request whose token names a *replaced*
/// session is refused with `ST_INVALID_DEVICE_STATE` and touches nothing.  That
/// refusal is the whole point of 1.0.0.24: the live session belongs to somebody
/// else.
unsafe fn claim_session(
    live: &mut LiveState,
    owner: p1d::Owner,
    what: &str,
    token: u32,
    hint: u32,
) -> Claim {
    match owner {
        p1d::Owner::Live(i) => Claim::Slot(i),
        p1d::Owner::Legacy(i) => {
            live.legacy_requests = live.legacy_requests.saturating_add(1);
            live.sessions[i].legacy_requests = live.sessions[i].legacy_requests.saturating_add(1);
            if live.sessions[i].legacy_requests <= 3 {
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "{}: legacy request without a session token{} -> attributed to token {} (only session open; it is the only way to serve a pre-1.0.0.24 client)",
                    what,
                    if hint != 0 { " (host-id hint matched)" } else { "" },
                    live.sessions[i].token
                );
                io_log_line(line.as_str());
            }
            Claim::Slot(i)
        }
        p1d::Owner::Stale => {
            live.ownership_rejects = live.ownership_rejects.saturating_add(1);
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "{}: session {} is not the live session (live: {}), request refused -> nothing touched (ownership_rejects={})",
                what,
                token_or_hint(token, hint),
                live_session_summary(live).as_str(),
                live.ownership_rejects
            );
            io_log_line(line.as_str());
            Claim::Refuse(ST_INVALID_DEVICE_STATE)
        }
        p1d::Owner::Ambiguous => {
            live.ownership_rejects = live.ownership_rejects.saturating_add(1);
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "{}: legacy request without a session token while {} sessions are open (live: {}) -> cannot be attributed, refused",
                what,
                live.open_sessions(),
                live_session_summary(live).as_str()
            );
            io_log_line(line.as_str());
            Claim::Refuse(ST_INVALID_DEVICE_STATE)
        }
        p1d::Owner::NoSession => {
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(line, "{}: no session open (call OPEN first)", what);
            io_log_line(line.as_str());
            Claim::Refuse(ST_INVALID_DEVICE_STATE)
        }
    }
}

/// `token` if the request carried one, else the host-id hint, else 0.
fn token_or_hint(token: u32, hint: u32) -> u32 {
    if token != vmedia_abi::VMEDIA_NO_SESSION_TOKEN {
        token
    } else {
        hint
    }
}

/// `token=1/host=0, token=2/host=3` for the log lines.
fn live_session_summary(live: &LiveState) -> virtio_media::LineBuf {
    let mut out = virtio_media::LineBuf::new();
    let mut first = true;
    for s in live.sessions.iter() {
        if !s.open {
            continue;
        }
        let _ = write!(
            out,
            "{}{}/host={}",
            if first { "" } else { ", " },
            s.token,
            s.host_id
        );
        first = false;
    }
    if first {
        let _ = write!(out, "none");
    }
    out
}

unsafe fn handle_ioctl(
    device: wdf::WDFDEVICE,
    request: wdf::WDFREQUEST,
    out_len: usize,
    in_len: usize,
    code: u32,
) -> (u32, usize) {
    let Some(idx) = slot_lookup(device) else {
        return (ST_DEVICE_NOT_READY, 0);
    };
    let live_ptr = {
        let slots = ptr::addr_of!(SLOTS) as *const DevSlot;
        (*slots.add(idx)).live
    };
    if live_ptr.is_null() {
        return (ST_DEVICE_NOT_READY, 0);
    }
    let live = &mut *live_ptr;
    live.ioctls = live.ioctls.saturating_add(1);
    let encoder_close=!live.is_decoder&&code==vmedia_abi::VM_IOCTL_CLOSE;
    if live.io.mmio.harvest_events().is_err()&&!encoder_close { return (ST_INVALID_DEVICE_STATE, 0); }
    if let Some(events) = live.io.mmio.events.as_mut() { events.sync_owners(&live.sessions, live.encoder); }

    if !live.is_decoder {
        if code!=vmedia_abi::VM_IOCTL_OPEN && live.encoder.open &&
            !live.encoder.owns_file(request_file_object(request) as usize){return(ST_INVALID_DEVICE_STATE,0)}
        let result = match code {
            vmedia_abi::VM_IOCTL_OPEN => ioctl_encoder_open(request, in_len, out_len, live),
            vmedia_abi::VM_IOCTL_CLOSE => ioctl_encoder_close(request, in_len, live),
            vmedia_abi::VM_IOCTL_ENC_CONFIG => ioctl_encoder_config(request,in_len,out_len,live),
            vmedia_abi::VM_IOCTL_ENC_QUEUE_INPUT => ioctl_encoder_queue_input(request,in_len,live),
            vmedia_abi::VM_IOCTL_ENC_GET_PACKET => ioctl_encoder_get_packet(request,in_len,out_len,live),
            vmedia_abi::VM_IOCTL_ENC_DRAIN => ioctl_encoder_drain(request,in_len,live),
            vmedia_abi::VM_IOCTL_ENC_SET_BITRATE => ioctl_encoder_set_bitrate(request,in_len,live),
            vmedia_abi::VM_IOCTL_ENC_FLUSH => {
                let (token, _) = unsafe { session_hints(request, Some(8), None) };
                if !live.encoder.open || token != live.encoder.token {
                    (ST_INVALID_DEVICE_STATE, 0)
                } else {
                    io_log_line("encoder v1 request refused: reverse V4L2 buffer queues are not configured");
                    (ST_NOT_SUPPORTED, 0)
                }
            }
            _ => (ST_INVALID_DEVICE_REQUEST, 0),
        };
        if let Some(events) = live.io.mmio.events.as_mut() { events.sync_owners(&live.sessions, live.encoder); }
        let _ = live.io.mmio.harvest_events();
        if live.io.mmio.poisoned() { return (ST_INVALID_DEVICE_STATE, 0); }
        return result;
    }

    // SESSION-OWNERSHIP (1.0.0.24): resolve which session this request belongs
    // to **once**, here, before any handler can touch device state.  OPEN is the
    // only code that does not need one: it allocates the next generation.
    let is_open = code == vmedia_abi::VM_IOCTL_OPEN;
    let (token_off, hint_off) = session_hint_offsets(code);
    let (token, hint) = if is_open {
        (0, 0)
    } else {
        unsafe { session_hints(request, token_off, hint_off) }
    };
    if matches!(code, vmedia_abi::VM_IOCTL_SEND_BITSTREAM_TAG | vmedia_abi::VM_IOCTL_GET_FRAME_TAG | vmedia_abi::VM_IOCTL_MAP_FRAME_TAG) && token == 0 { return (ST_INVALID_PARAMETER, 0); }
    let owner = if is_open {
        p1d::Owner::NoSession
    } else {
        live.resolve(token, hint)
    };

    let result = match code {
        vmedia_abi::VM_IOCTL_OPEN => ioctl_open(request, in_len, out_len, live),
        vmedia_abi::VM_IOCTL_SEND_BITSTREAM | vmedia_abi::VM_IOCTL_SEND_BITSTREAM_EX | vmedia_abi::VM_IOCTL_SEND_BITSTREAM_TAG => {
            ioctl_send(request, in_len, out_len, live, owner, code, token, hint)
        }
        vmedia_abi::VM_IOCTL_GET_FRAME | vmedia_abi::VM_IOCTL_GET_FRAME_TAG => {
            ioctl_get_frame(request, in_len, out_len, live, owner, token, hint, code == vmedia_abi::VM_IOCTL_GET_FRAME_TAG)
        }
        vmedia_abi::VM_IOCTL_CLOSE => ioctl_close(request, in_len, live, owner, token, hint),
        vmedia_abi::VM_IOCTL_FLUSH => {
            ioctl_flush(request, in_len, out_len, live, owner, token, hint)
        }
        vmedia_abi::VM_IOCTL_MAP_FRAME | vmedia_abi::VM_IOCTL_MAP_FRAME_TAG => {
            ioctl_map_frame(request, in_len, out_len, live, owner, token, hint, code == vmedia_abi::VM_IOCTL_MAP_FRAME_TAG)
        }
        vmedia_abi::VM_IOCTL_RELEASE_FRAME => {
            ioctl_release_frame(request, in_len, out_len, live, owner, token, hint)
        }
        _ => (ST_INVALID_DEVICE_REQUEST, 0),
    };
    // Snapshot old owners throughout CLOSE/FLUSH command waits. New generations
    // are registered only after their OPEN response and handler state commit.
    let _ = live.io.mmio.harvest_events();
    if let Some(events) = live.io.mmio.events.as_mut() { events.sync_owners(&live.sessions, live.encoder); }
    if live.io.mmio.poisoned() { (ST_INVALID_DEVICE_STATE, 0) } else { result }
}

unsafe fn ioctl_encoder_open(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
) -> (u32, usize) {
    if live.encoder.open {
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    let file=request_file_object(request);
    if file.is_null(){return(ST_INVALID_DEVICE_STATE,0)}
    let (inp, got) = match request_input(request, size_of::<vmedia_abi::VM_OPEN_IN>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if got < size_of::<vmedia_abi::VM_OPEN_IN>() || in_len < got {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let open = ptr::read_unaligned(inp as *const vmedia_abi::VM_OPEN_IN);
    if open.Kind != 1 || open.Codec != vmedia_abi::VM_OPEN_CODEC_H264 {
        return (ST_INVALID_PARAMETER, 0);
    }
    let (outp, olen) = match request_output(request, size_of::<vmedia_abi::VM_OPEN_OUT>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < size_of::<vmedia_abi::VM_OPEN_OUT>() || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }

    let req = live.io.req_base();
    let resp = live.io.resp_base();
    let host_id = match p1d::open_session(
        &mut live.io.mmio,
        &mut live.io.q0,
        &req,
        &resp,
        &mut IoLog,
    ) {
        Ok(id) => id,
        Err(e) => return (map_error(e), 0),
    };
    let token = live.alloc_token();
    if live.encoder.install(host_id, token).is_err() {
        let mut cfg = SessionConfig::empty();
        let _ = p1d::close_session(
            &mut live.io.mmio,
            &mut live.io.q0,
            &req,
            &resp,
            host_id,
            &mut cfg,
            p1d::COMMAND_SPINS,
            &mut IoLog,
        );
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    // install() succeeded above and every user OPEN must have a WDF file.
    let _=live.encoder.bind_file(token,file as usize);
    live.opens = live.opens.saturating_add(1);
    let out = vmedia_abi::VM_OPEN_OUT {
        SessionId: host_id,
        IsDecoder: 0,
        DeviceCaps: live.device_caps,
        DeviceType: live.device_type,
        PoolSize: live.io.pool_len.min(u32::MAX as usize) as u32,
        DriverVersion: vmedia_abi::VMEDIA_DRIVER_VERSION,
        SessionToken: token,
        Reserved1: 0,
    };
    ptr::write_unaligned(outp as *mut vmedia_abi::VM_OPEN_OUT, out);
    io_log_line("OPEN encoder: independent host owner created for H.264; encoding queues are not configured");
    (ST_SUCCESS, size_of::<vmedia_abi::VM_OPEN_OUT>())
}

unsafe fn ioctl_encoder_queue_input(request:wdf::WDFREQUEST,in_len:usize,live:&mut LiveState)->(u32,usize){
    if !live.encoder.open||!live.encoder_slot.counters().queues_configured{return(ST_INVALID_DEVICE_STATE,0)}
    let header=size_of::<vmedia_abi::VM_ENCODER_INPUT>();
    let (inp,got)=match request_input(request,header){Ok(v)=>v,Err(st)=>return(st,0)};
    if inp.is_null()||got<header||in_len<header{return(ST_BUFFER_TOO_SMALL,0)}
    let frame=ptr::read_unaligned(inp as *const vmedia_abi::VM_ENCODER_INPUT);
    if frame.Size as usize!=header||frame.DataSize as usize!=got-header||in_len!=got||frame.SessionToken!=live.encoder.token{return(ST_INVALID_PARAMETER,0)}
    let payload=core::slice::from_raw_parts(inp.add(header),frame.DataSize as usize);
    let req=live.io.req_base();let resp=live.io.resp_base();
    match p1d::queue_encoder_input(&mut live.io.mmio,&mut live.io.q0,live.encoder.host_id,
        &req,&resp,live.io.pool_va,live.io.pool_len,
        &mut live.encoder_slot,&frame,payload,&mut IoLog){
        Ok(())=>(ST_SUCCESS,0),
        Err(e)=>(map_error(e),0),
    }
}

unsafe fn ioctl_encoder_config(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
) -> (u32, usize) {
    if !live.encoder.open { return (ST_INVALID_DEVICE_STATE, 0); }
    let (inp, got) = match request_input(request, size_of::<vmedia_abi::VM_ENCODER_CONFIG>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if got < size_of::<vmedia_abi::VM_ENCODER_CONFIG>() || in_len < size_of::<vmedia_abi::VM_ENCODER_CONFIG>() {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let mut config = ptr::read_unaligned(inp as *const vmedia_abi::VM_ENCODER_CONFIG);
    if config.SessionToken != live.encoder.token { return (ST_INVALID_DEVICE_STATE, 0); }
    if crate::encoder_abi::validate_config(&config).is_err() { return (ST_INVALID_PARAMETER, 0); }
    let (outp, olen) = match request_output(request, size_of::<vmedia_abi::VM_ENCODER_CONFIG>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < size_of::<vmedia_abi::VM_ENCODER_CONFIG>() || out_len < size_of::<vmedia_abi::VM_ENCODER_CONFIG>() {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    if live.encoder_slot.configure(&config).is_err() { return (ST_INVALID_DEVICE_STATE, 0); }
    let req = live.io.req_base();
    let resp = live.io.resp_base();
    let setup = p1d::configure_encoder_queues(
        &mut live.io.mmio,
        &mut live.io.q0,
        &req,
        &resp,
        live.encoder.host_id,
        live.io.pool_va,
        live.io.pool_len,
        live.io.pool_len / 2,
        &config,
        4,
        4,
        &mut live.encoder_slot,
        &mut IoLog,
    );
    if let Err(e) = setup {
        live.encoder_slot.abort_configure();
        return (map_error(e), 0);
    }
    config = live.encoder_slot.negotiated_config();
    ptr::write_unaligned(outp as *mut vmedia_abi::VM_ENCODER_CONFIG, config);
    io_log_line("ENC_CONFIG: NV12 OUTPUT/H264 CAPTURE queues MMAP'd and STREAMON; frame/packet IOCTL bridge pending");
    (ST_SUCCESS, size_of::<vmedia_abi::VM_ENCODER_CONFIG>())
}

unsafe fn ioctl_encoder_set_bitrate(request:wdf::WDFREQUEST,in_len:usize,live:&mut LiveState)->(u32,usize){
    if !live.encoder.open||!live.encoder_slot.counters().queues_configured||live.encoder_slot.counters().drain_pending||live.encoder_slot.is_drained(){return(ST_INVALID_DEVICE_STATE,0)}
    let size=size_of::<vmedia_abi::VM_ENCODER_RATE_CONTROL>();
    let (inp,got)=match request_input(request,size){Ok(v)=>v,Err(st)=>return(st,0)};
    if inp.is_null()||got!=size||in_len!=size{return(ST_INVALID_PARAMETER,0)}
    let rate=ptr::read_unaligned(inp as *const vmedia_abi::VM_ENCODER_RATE_CONTROL);
    if crate::encoder_abi::validate_rate_control(&rate,live.encoder.token).is_err(){return(ST_INVALID_PARAMETER,0)}
    let req=live.io.req_base();let resp=live.io.resp_base();
    match p1d::encoder_set_control(&mut live.io.mmio,&mut live.io.q0,&req,&resp,live.encoder.host_id,0x009909CF,rate.Bitrate,&mut IoLog){
        Ok(())=>{live.encoder_slot.set_bitrate(rate.Bitrate);(ST_SUCCESS,0)},Err(e)=>(map_error(e),0)
    }
}

unsafe fn ioctl_encoder_drain(request:wdf::WDFREQUEST,in_len:usize,live:&mut LiveState)->(u32,usize){
    if !live.encoder.open{return(ST_INVALID_DEVICE_STATE,0)}
    let size=size_of::<vmedia_abi::VM_ENCODER_CONTROL>();
    let (inp,got)=match request_input(request,size){Ok(v)=>v,Err(st)=>return(st,0)};
    if inp.is_null()||got!=size||in_len!=size{return(ST_INVALID_PARAMETER,0)}
    let control=ptr::read_unaligned(inp as *const vmedia_abi::VM_ENCODER_CONTROL);
    if let Err(e)=crate::encoder_abi::validate_control(&control,live.encoder.token){
        return(if e==crate::encoder_abi::EncoderRequestError::SessionToken{ST_INVALID_DEVICE_STATE}else{ST_INVALID_PARAMETER},0)
    }
    if live.encoder_slot.begin_drain().is_err(){return(ST_INVALID_DEVICE_STATE,0)}
    if live.encoder_slot.empty_drain_pending(){return(ST_SUCCESS,0)}
    let req=live.io.req_base();let resp=live.io.resp_base();
    match p1d::encoder_stop(&mut live.io.mmio,&mut live.io.q0,&req,&resp,live.encoder.host_id,&mut IoLog){
        Ok(())=>(ST_SUCCESS,0),
        Err(e)=>{live.encoder_slot.cancel_drain();(map_error(e),0)}
    }
}

unsafe fn ioctl_encoder_get_packet(
    request:wdf::WDFREQUEST,in_len:usize,out_len:usize,live:&mut LiveState,
)->(u32,usize){
    if !live.encoder.open{return(ST_INVALID_DEVICE_STATE,0)}
    let header=size_of::<vmedia_abi::VM_ENCODER_GET_PACKET_IN>();
    let (inp,got)=match request_input(request,header){Ok(v)=>v,Err(st)=>return(st,0)};
    if inp.is_null()||got<header||in_len<header{return(ST_BUFFER_TOO_SMALL,0)}
    let req_packet=ptr::read_unaligned(inp as *const vmedia_abi::VM_ENCODER_GET_PACKET_IN);
    let (outp,olen)=match request_output(request,size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>()){Ok(v)=>v,Err(st)=>return(st,0)};
    let capacity=match crate::encoder_abi::validate_get_packet(&req_packet,live.encoder.token,olen){Ok(v)=>v,Err(crate::encoder_abi::EncoderRequestError::PacketCapacity)=>return(ST_BUFFER_TOO_SMALL,0),Err(crate::encoder_abi::EncoderRequestError::SessionToken)=>return(ST_INVALID_DEVICE_STATE,0),Err(_)=>return(ST_INVALID_PARAMETER,0)};
    if !live.encoder_slot.counters().queues_configured{return(ST_INVALID_DEVICE_STATE,0)}
    if live.encoder_slot.empty_drain_pending(){
        let mut info=vmedia_abi::VM_ENCODER_PACKET_INFO::default();
        info.Version=vmedia_abi::VM_ENCODER_ABI_VERSION;info.Size=size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>() as u32;
        info.SessionToken=live.encoder.token;info.Flags=vmedia_abi::VM_ENCODER_PACKET_FLAG_DRAIN_DONE;
        if live.encoder_slot.complete_drain().is_err(){return(ST_INVALID_DEVICE_STATE,0)}
        ptr::write_unaligned(outp as *mut vmedia_abi::VM_ENCODER_PACKET_INFO,info);
        return(ST_SUCCESS,size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>())
    }
    if live.encoder_slot.is_drained(){return(ST_INVALID_DEVICE_STATE,0)}
    let dev=live.io.mmio.wdf_device;
    let max_spins=if req_packet.TimeoutMs==0{0}else{req_packet.TimeoutMs.saturating_mul(2)};
    for spin in 0..=max_spins{
        let dev=live.io.mmio.wdf_device;let mut reap_wait=move||unsafe{irq::wait(dev)};
        if virtio_media::reap_async(&mut live.io.mmio,&mut live.io.q0,&mut reap_wait,0,false,&mut IoLog).is_err(){return(ST_INVALID_DEVICE_STATE,0)}
        let async_errno=virtio_media::take_async_err(&mut live.io.q0,p1d::VMEDIA_MAX_SESSIONS as u8);
        if async_errno!=0{return(map_error(virtio_media::Error::Errno(async_errno)),0)}
        if live.io.mmio.harvest_events().is_err(){return(ST_INVALID_DEVICE_STATE,0)}
        let notice=if let Some(p)=live.encoder_slot.pending_packet(){
            Some(p1d::EncoderNotice::Packet{index:p.index,bytesused:p.bytesused,timestamp:p.timestamp_us,timestamp_valid:p.timestamp_valid,keyframe:p.keyframe,last:p.last})
        }else{
            live.io.mmio.events.as_mut().and_then(|e|e.pop_encoder_notice(live.encoder.host_id,live.encoder.token))
        };
        if let Some(notice)=notice{
            match notice{
                p1d::EncoderNotice::InputDone{index,..}=>{
                    let Some(id)=live.encoder_slot.input_buffer_id(index)else{return(ST_INVALID_DEVICE_STATE,0)};
                    if live.encoder_slot.input_done(id).is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                    continue
                }
                p1d::EncoderNotice::Error(errno)=>return(map_error(virtio_media::Error::Errno(errno)),0),
                p1d::EncoderNotice::Packet{index,bytesused,timestamp,timestamp_valid,keyframe,last}=>{
                    if live.encoder_slot.pending_packet().is_none()&&live.encoder_slot.set_pending_packet(crate::encoder_state::EncoderPendingPacket{index,bytesused,timestamp_us:timestamp,timestamp_valid,keyframe,last}).is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                    let Some(range)=live.encoder_slot.pool_range(index,1)else{return(ST_INVALID_DEVICE_STATE,0)};
                    if bytesused>range.buffer_len||range.offset>live.io.pool_len as u64||bytesused as usize>live.io.pool_len.saturating_sub(range.offset as usize){
                        return(ST_INVALID_DEVICE_STATE,0)
                    }
                    if bytesused as usize>capacity{return(ST_BUFFER_TOO_SMALL,0)}
                    let src=unsafe{live.io.pool_va.add(range.offset as usize)};
                    if p1d::POOL_CACHED.load(Ordering::SeqCst){p1d::cache_invalidate_range(src,bytesused as usize)}
                    let drain_done=last;
                    if !timestamp_valid&&bytesused!=0{
                        return(ST_DATA_ERROR,0)
                    }
                    if bytesused==0&&!drain_done{
                        let req=live.io.req_base();let resp=live.io.resp_base();
                        if p1d::requeue_encoder_capture(&mut live.io.mmio,&mut live.io.q0,&req,&resp,live.encoder.host_id,&live.encoder_slot,index,&mut IoLog).is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                        let _=live.encoder_slot.clear_pending_packet(index);
                        continue
                    }
                    let mut info=vmedia_abi::VM_ENCODER_PACKET_INFO::default();
                    info.Version=vmedia_abi::VM_ENCODER_ABI_VERSION;info.Size=size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>() as u32;
                    info.SessionToken=live.encoder.token;info.BytesUsed=bytesused;
                    info.Flags=crate::encoder_abi::encoder_packet_flags(keyframe,drain_done);
                    info.Timestamp=timestamp.saturating_mul(10);
                    unsafe{ptr::write_unaligned(outp as *mut vmedia_abi::VM_ENCODER_PACKET_INFO,info);if bytesused!=0{ptr::copy_nonoverlapping(src,outp.add(size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>()),bytesused as usize)}}
                    if !drain_done{
                        let req=live.io.req_base();let resp=live.io.resp_base();
                        if p1d::requeue_encoder_capture(&mut live.io.mmio,&mut live.io.q0,&req,&resp,live.encoder.host_id,&live.encoder_slot,index,&mut IoLog).is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                        if live.encoder_slot.packet_done().is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                    }
                    if drain_done && live.encoder_slot.complete_drain().is_err(){return(ST_INVALID_DEVICE_STATE,0)}
                    let _=live.encoder_slot.clear_pending_packet(index);
                    return(ST_SUCCESS,size_of::<vmedia_abi::VM_ENCODER_PACKET_INFO>()+bytesused as usize)
                }
                p1d::EncoderNotice::Other=>{}
            }
        }
        if spin==max_spins{break}
        irq::wait(dev);
    }
    (ST_IO_TIMEOUT,0)
}

unsafe fn ioctl_encoder_close(
    request: wdf::WDFREQUEST,
    in_len: usize,
    live: &mut LiveState,
) -> (u32, usize) {
    if !live.encoder.open {
        return (ST_SUCCESS, 0);
    }
    let (inp, got) = match request_input(request, size_of::<vmedia_abi::VM_CLOSE_IN>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if got < size_of::<vmedia_abi::VM_CLOSE_IN>() || in_len < got {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let close = ptr::read_unaligned(inp as *const vmedia_abi::VM_CLOSE_IN);
    if close.Reserved0 != 0 || close.Flags != 0 {
        return (ST_INVALID_PARAMETER, 0);
    }
    if !live.encoder.owns(close.SessionToken) {
        return (ST_SUCCESS, 0);
    }
    if close.SessionId != 0 && close.SessionId != live.encoder.host_id {
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    close_encoder_owner(live,close.SessionToken)
}

/// Common explicit/file-cleanup teardown. A failed transport stays poisoned;
/// local ownership is always retired, never silently reused with old DMA.
unsafe fn close_encoder_owner(live:&mut LiveState,token:u32)->(u32,usize){
    if !live.encoder.owns(token){return(ST_SUCCESS,0)}
    if live.io.mmio.poisoned(){
        let _=live.encoder.clear(token);
        io_log_line("encoder CLOSE: retired file owner; poisoned transport requires device recovery");
        return(ST_INVALID_DEVICE_STATE,0)
    }
    let req = live.io.req_base();
    let resp = live.io.resp_base();
    p1d::release_encoder_queues(&mut live.io.mmio,&mut live.io.q0,&req,&resp,
        live.encoder.host_id,&mut live.encoder_slot,&mut IoLog);
    let mut cfg = SessionConfig::empty();
    let result = p1d::close_session(
        &mut live.io.mmio,
        &mut live.io.q0,
        &req,
        &resp,
        live.encoder.host_id,
        &mut cfg,
        p1d::COMMAND_SPINS,
        &mut IoLog,
    );
    if result.is_ok(){
        let _=live.io.mmio.harvest_events();
        if let Some(events)=live.io.mmio.events.as_mut(){
            while events.pop_encoder_notice(live.encoder.host_id,token).is_some(){}
        }
        let _=virtio_media::take_async_err(&mut live.io.q0,p1d::VMEDIA_MAX_SESSIONS as u8);
    }
    let _ = live.encoder.clear(token);
    live.closes = live.closes.saturating_add(1);
    match result {
        Ok(()) => (ST_SUCCESS, 0),
        Err(e) => (map_error(e), 0),
    }
}

/// Spins for the recovery CLOSE that runs inside OPEN (each spin stalls 500 us,
/// so this is roughly half a second).
const STALE_CLOSE_SPINS: u32 = 1000;

unsafe fn ioctl_open(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
) -> (u32, usize) {
    // ---- 1. which slot? --------------------------------------------------
    //
    // SESSION-OWNERSHIP (1.0.0.24): OPEN never touches a session that belongs
    // to somebody else.  1.0.0.23 closed "the" open session here, which is
    // exactly what Chromium's two decoder wrappers hit: the second OPEN
    // destroyed the first decoder's host session, and the first decoder's CLOSE
    // then destroyed the second's (this function's sibling, ioctl_close).
    //
    // The rule now is: use a free slot; if every slot is taken, close the
    // **oldest** session (the one whose client has been replaced) and use its
    // slot -- never a silent "fail forever" (the P2-2e wedge), and never the
    // live session of a client that is still working.
    let slot = match live.free_slot() {
        Some(i) => i,
        None => {
            let Some(old) = live.oldest() else {
                // Unreachable: free_slot() only fails when every slot is open.
                return (ST_INSUFFICIENT_RESOURCES, 0);
            };
            let old_host = live.sessions[old].host_id;
            let old_token = live.sessions[old].token;
            live.stale_closes = live.stale_closes.saturating_add(1);
            let mut head = virtio_media::LineBuf::new();
            let _ = write!(
                head,
                "OPEN: all {} session slot(s) busy (live: {}) -> replacing the oldest (token {}, host {}) before the new one",
                p1d::VMEDIA_MAX_SESSIONS,
                live_session_summary(live).as_str(),
                old_token,
                old_host
            );
            io_log_line(head.as_str());
            let req = live.io.req_base();
            let resp = live.io.resp_base();
            let closed = match p1d::close_session(
                &mut live.io.mmio,
                &mut live.io.q0,
                &req,
                &resp,
                old_host,
                &mut live.sessions[old].cfg,
                STALE_CLOSE_SPINS,
                &mut IoLog,
            ) {
                Ok(()) => {
                    io_log_line("OPEN: oldest session closed");
                    true
                }
                Err(e) => {
                    let _ = map_error(e);
                    io_log_line("OPEN: device refused the stale CLOSE -> dropping the guest state anyway");
                    false
                }
            };
            let _ = closed;
            // A mapping of that session describes pool ranges the sweep below is
            // about to MUNMAP, so it goes first.
            let _ = unsafe { drain_mappings(&mut live.sessions[old], "OPEN(stale)") };
            let owed = p1d::pending_mappings(&live.sessions[old].cfg);
            if owed != 0 {
                let n = p1d::release_all_mappings(
                    &mut live.io.mmio,
                    &mut live.io.q0,
                    &req,
                    &resp,
                    &mut live.sessions[old].cfg,
                    &mut IoLog,
                );
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "OPEN: pool sweep of token {} released {} of {} leftover mapping(s), {} still owed",
                    old_token,
                    n,
                    owed,
                    p1d::pending_mappings(&live.sessions[old].cfg)
                );
                io_log_line(line.as_str());
            }
            // Keep the slot's token allocation in `alloc_token`, but make the
            // dead generation unusable from here on: the slot is reset below.
            live.sessions[old].clear();
            old
        }
    };
    // ---- 2. validate the request (no state touched yet) ------------------
    let (inp, got) = match request_input(request, 0) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    let mut kind = 0u32;
    if got >= 4 && !inp.is_null() {
        kind = virtio_media::read_u32(core::slice::from_raw_parts(inp, got), 0);
    }
    if kind > 1 {
        return (ST_INVALID_PARAMETER, 0);
    }
    let is_decoder = live.is_decoder;
    let device_caps = live.device_caps;
    let device_type = live.device_type;
    if (kind == 0) != is_decoder {
        io_log_line("OPEN: kind does not match this function (decoder vs encoder)");
        return (ST_INVALID_PARAMETER, 0);
    }
    // P-BATCH VP9/HEVC: VM_OPEN_IN.Codec (byte 4) picks the coded format the
    // host session is configured for.  It used to be a must-be-zero `Flags` field
    // and was never read, so a pre-VP9 client sending 0 keeps H.264 exactly as
    // before; an older driver used with a new UMD simply ignores it (the UMD
    // checks DriverVersion before it tries VP9 or HEVC).
    let mut codec = vmedia_abi::VM_OPEN_CODEC_H264;
    if got >= 8 && !inp.is_null() {
        codec = virtio_media::read_u32(core::slice::from_raw_parts(inp, got), 4);
    }
    if codec > vmedia_abi::VM_OPEN_CODEC_HEVC_MAIN10 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "OPEN: unsupported codec selector {} (0 = H264, 1 = VP9, 2 = HEVC, 3 = AV1, 4 = HEVC-Main10)",
            codec
        );
        io_log_line(line.as_str());
        return (ST_INVALID_PARAMETER, 0);
    }
    if codec != vmedia_abi::VM_OPEN_CODEC_H264 && !is_decoder {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "OPEN: codec selector {} (VP9/HEVC/AV1/HEVC-Main10) is decoder-only; this is the encoder function",
            codec
        );
        io_log_line(line.as_str());
        return (ST_INVALID_PARAMETER, 0);
    }
    let (outp, olen) = match request_output(request, size_of::<vmedia_abi::VM_OPEN_OUT>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < size_of::<vmedia_abi::VM_OPEN_OUT>() || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    // ---- 3. open the host session on the chosen slot ---------------------
    let pool_len = live.io.pool_len as u32;
    let (io, s) = live.split(slot);
    // A slot that was replaced above still owes its old cfg's MUNMAPs, and the
    // open below must not start on top of pool ranges this device still holds.
    let _ = unsafe { drain_mappings(s, "OPEN") };
    {
        let owed = p1d::pending_mappings(&s.cfg);
        if owed != 0 {
            let req = io.req_base();
            let resp = io.resp_base();
            let n = p1d::release_all_mappings(
                &mut io.mmio,
                &mut io.q0,
                &req,
                &resp,
                &mut s.cfg,
                &mut IoLog,
            );
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "OPEN: pool sweep released {} of {} leftover mapping(s), {} still owed",
                n,
                owed,
                p1d::pending_mappings(&s.cfg)
            );
            io_log_line(line.as_str());
        }
        s.cfg = SessionConfig::empty();
    }
    let req = io.req_base();
    let resp = io.resp_base();
    // The split borrow ends with this call: everything below touches
    // `live.sessions[slot]` directly (NLL: `io`/`s` are not used again).
    let opened = p1d::open_session(&mut io.mmio, &mut io.q0, &req, &resp, &mut IoLog);
    match opened {
        Ok(session_id) => {
            // The generation is allocated only once the host session exists, so
            // a failed OPEN cannot burn a token the client will never see.
            let token = live.alloc_token();
            {
                let s = &mut live.sessions[slot];
                s.open = true;
                s.token = token;
                s.host_id = session_id;
                s.codec = codec;
                s.pending_aus = 0;
                s.frames = p1d::PendingFrames::empty();
                s.aus_sent = 0;
                s.frames_got = 0;
                s.cfg = SessionConfig::empty();
            }
            live.opens = live.opens.saturating_add(1);
            let mut opened = virtio_media::LineBuf::new();
            // E173: a bare else printed H264 for AV1 (codec 3), so the ring said
            // `codec=H264` right before `S_FMT OUTPUT 'AV01'` -- confusing
            // exactly when someone reads the log to see which codec failed.
            let codec_name = match codec {
                vmedia_abi::VM_OPEN_CODEC_VP9 => "VP9",
                vmedia_abi::VM_OPEN_CODEC_HEVC => "HEVC",
                vmedia_abi::VM_OPEN_CODEC_AV1 => "AV1",
                vmedia_abi::VM_OPEN_CODEC_HEVC_MAIN10 => "HEVC-Main10",
                _ => "H264",
            };
            let _ = write!(
                opened,
                "OPEN: token {} = slot {} host session {} open (opens={} closes={} failed_closes={} stale_closes={} open_sessions={}) codec={}",
                token,
                slot,
                session_id,
                live.opens,
                live.closes,
                live.failed_closes,
                live.stale_closes,
                live.open_sessions(),
                codec_name
            );
            io_log_line(opened.as_str());
            let out = vmedia_abi::VM_OPEN_OUT {
                SessionId: session_id,
                IsDecoder: if is_decoder { 1 } else { 0 },
                DeviceCaps: device_caps,
                DeviceType: device_type,
                PoolSize: pool_len,
                DriverVersion: vmedia_abi::VMEDIA_DRIVER_VERSION,
                SessionToken: token,
                Reserved1: 0,
            };
            ptr::write_unaligned(outp as *mut vmedia_abi::VM_OPEN_OUT, out);
            (ST_SUCCESS, size_of::<vmedia_abi::VM_OPEN_OUT>())
        }
        Err(e) => {
            // P2-2f: this path never marks the slot open, so it cannot wedge the
            // device.  A timeout can still leave an untracked session on the
            // host (we never learned its id) -- log that instead of guessing an
            // id to CLOSE.
            io_log_line("OPEN: failed before a session id was known -> no guest state to clear (see the ioctl error above)");
            (map_error(e), 0)
        }
    }
}

unsafe fn ioctl_send(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    code: u32,
    token: u32,
    hint: u32,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): the session has to be the caller's before a
    // single byte reaches the host.  A SEND from a replaced decoder would feed
    // another session's host decoder an access unit of a different sequence
    // (wrong SPS/PPS, wrong reference frames) -- the frame that comes out is
    // garbage and the *live* client gets blamed for it.
    let slot = match unsafe { claim_session(live, owner, "SEND", token, hint) } {
        Claim::Slot(i) => i,
        Claim::Refuse(st) => return (st, 0),
    };
    if !live.is_decoder {
        return (ST_NOT_SUPPORTED, 0);
    }
    // The extended header carries the token; the legacy code cannot.  Read the
    // header size from the IOCTL code, not from the payload (the access unit
    // follows immediately, so a wrong guess would corrupt the bitstream).
    let send_ex = code == vmedia_abi::VM_IOCTL_SEND_BITSTREAM_EX;
    let send_tag = code == vmedia_abi::VM_IOCTL_SEND_BITSTREAM_TAG;
    let header_len = if send_tag { size_of::<vmedia_abi::VM_SEND_IN_TAG>() } else if send_ex {
        size_of::<vmedia_abi::VM_SEND_IN_EX>()
    } else {
        size_of::<vmedia_abi::VM_SEND_IN>()
    };
    let (inp, got) = match request_input(request, header_len) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if got < header_len {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let header = core::slice::from_raw_parts(inp, got);
    let width = virtio_media::read_u32(header, 0);
    let height = virtio_media::read_u32(header, 4);
    let size = virtio_media::read_u32(header, 8);
    let flags = virtio_media::read_u32(header, 12);
    if size == 0 || (size as usize) > got - header_len {
        io_log_line("SEND: Size does not fit the input buffer");
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let (outp, olen) = match request_output(request, size_of::<vmedia_abi::VM_SEND_OUT>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < size_of::<vmedia_abi::VM_SEND_OUT>() || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let tag = if send_tag { virtio_media::read_u64(header, 24) } else { 0 };
    if send_tag && (tag == 0 || tag > i64::MAX as u64 || virtio_media::read_u32(header,20) != 0 || flags & !1 != 0) { return (ST_INVALID_PARAMETER, 0); }
    let data = core::slice::from_raw_parts(inp.add(header_len), size as usize);
    // Read the session count before the split borrows `live` in two.
    let pool_share = live.open_sessions().max(1) as usize;
    // PER-SESSION-LIVESTATE (1.0.0.25): `split2` also hands back the *other*
    // slot of this function, so the event pump below can deliver a completion the
    // host addressed to that session instead of dropping it.
    let (io, s, peer) = live.split2(slot);
    let mut fan = p1d::Fanout::new(s.host_id, slot, peer);
    let req = io.req_base();
    let resp = io.resp_base();
    let drain = (flags & 1) != 0;
    // 1.0.0.25: an ERROR event that arrived for this session while the *other*
    // session's IOCTL was running was latched in the slot instead of failing that
    // other request.  Surface it here, where this session would have met it.
    let latched = p1d::take_event_err(s);
    if latched != 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "SEND: this session's ERROR event (errno={} ({})) was latched by the other session's pump -> failing this SEND",
            latched, -latched
        );
        io_log_line(line.as_str());
        return (map_error(virtio_media::Error::Errno(latched)), 0);
    }
    // 1.0.0.12: the per-AU QBUF is fire-and-forget, so its answer is reaped by a
    // later command.  Surface a refused one here (it means the host dropped that
    // access unit; the client must not wait a full GET_FRAME timeout for it).
    //
    // 1.0.0.25: only if *this* session submitted it (`take_async_err` checks the
    // owner tag); before that the latch was device-wide and one session's dropped
    // AU failed the other session's next SEND.
    let errno = virtio_media::take_async_err(&mut io.q0, slot as u8);
    if errno != 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "SEND: an earlier async QBUF of this session was refused errno={} ({}) -> that frame is lost",
            errno, -errno
        );
        io_log_line(line.as_str());
    }
    let out;
    // P3/1.0.0.10: the first SEND configures the session exactly as before; every
    // later SEND queues one more access unit on the same host session.  That is
    // what makes P/B frames decode: they keep their reference frames.
    if s.cfg.stop_failed {
        io_log_line("SEND refused: previous AU partially accepted, STOP failed; FLUSH/CLOSE required, do not replay");
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    if !s.cfg.configured {
        // 1.0.0.20 / E173: release anything a previous attempt still owes before
        // dropping the bookkeeping.  `SessionConfig::empty()` made those ranges
        // unreachable, so a configure that failed after mapping a buffer leaked
        // that pool range for the life of the device -- exactly the "next codec
        // fails too" half of E172.
        let owed = p1d::pending_mappings(&s.cfg);
        if owed != 0 {
            let req = io.req_base();
            let resp = io.resp_base();
            let released = p1d::release_all_mappings(
                &mut io.mmio,
                &mut io.q0,
                &req,
                &resp,
                &mut s.cfg,
                &mut IoLog,
            );
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "SEND: released {} of {} leftover mapping(s) from the previous configure attempt, {} still owed",
                released,
                owed,
                p1d::pending_mappings(&s.cfg)
            );
            io_log_line(line.as_str());
        }
        s.cfg = SessionConfig::empty();
        s.cfg.send_tag = tag;
        match p1d::configure_and_send(
            &mut io.mmio,
            &mut io.q0,
            &req,
            &resp,
            io.pool_va,
            io.pool_len,
            // SESSION-OWNERSHIP: the pool is one budget shared by every session
            // of this function, so each configure gets `pool / open_sessions`.
            // With one session open that is the whole pool (the pre-1.0.0.24
            // behaviour, unchanged); with two it is half each, which is what
            // keeps 2 x 720p inside the 64 MiB `media_host` pool instead of the
            // second session failing REQBUFS with ENOMEM.
            io.pool_len / pool_share,
            s.host_id,
            s.codec,
            width,
            height,
            data,
            drain,
            &mut s.cfg,
            &mut IoLog,
        ) {
            Ok(first_out) => {
                out = first_out;
            }
            Err(e) => {
                if s.cfg.stop_failed {
                    s.pending_aus = s.pending_aus.saturating_add(1);
                    s.aus_sent = s.aus_sent.saturating_add(1);
                }
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "SEND: configure failed ({} mapping(s) still owed); if STOP failed AU is partially accepted, no replay, FLUSH/CLOSE required",
                    p1d::pending_mappings(&s.cfg)
                );
                io_log_line(line.as_str());
                return (map_error(e), 0);
            }
        }
    } else {
        if width != s.cfg.width || height != s.cfg.height {
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "SEND: geometry {}x{} differs from the configured {}x{} (a mid-stream change needs STREAMOFF/REQBUFS, not supported)",
                width, height, s.cfg.width, s.cfg.height
            );
            io_log_line(line.as_str());
        }
        s.cfg.send_tag = tag;
        if let Err(e) = p1d::submit_access_unit(
            &mut io.mmio,
            &mut io.q0,
            &req,
            &resp,
            &mut fan,
            &mut s.cfg,
            &mut s.frames,
            data,
            drain,
            &mut IoLog,
        ) {
            if s.cfg.stop_failed {
                s.pending_aus = s.pending_aus.saturating_add(1);
                s.aus_sent = s.aus_sent.saturating_add(1);
            }
            return (map_error(e), 0);
        }
        out = vmedia_abi::VM_SEND_OUT {
            Width: s.cfg.width,
            Height: s.cfg.height,
            OutputSizeImage: s.cfg.output_sizeimage,
            CaptureSizeImage: s.cfg.capture_sizeimage,
            CaptureStride: s.cfg.capture_stride,
            CaptureCount: s.cfg.capture_count,
            Reserved0: 0,
            Reserved1: 0,
        };
    }
    s.pending_aus = s.pending_aus.saturating_add(1);
    s.aus_sent = s.aus_sent.saturating_add(1);
    ptr::write_unaligned(outp as *mut vmedia_abi::VM_SEND_OUT, out);
    if s.aus_sent <= 3 || s.aus_sent % 30 == 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "SEND ok: AU {} bytes, aus={} pending={} (free output mask 0x{:X}, async in-flight={})",
            size, s.aus_sent, s.pending_aus, s.cfg.out_free, io.q0.async_inflight
        );
        io_log_line(line.as_str());
    }
    (ST_SUCCESS, size_of::<vmedia_abi::VM_SEND_OUT>())
}

unsafe fn ioctl_get_frame(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    token: u32,
    hint: u32,
    tagged: bool,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): a GET_FRAME belongs to the session that sent
    // the access units.  It also *re-queues* a capture buffer, so serving a
    // replaced client here would hand the live session's buffer back to the
    // device twice.
    let slot = match unsafe { claim_session(live, owner, "GET_FRAME", token, hint) } {
        Claim::Slot(i) => i,
        Claim::Refuse(st) => return (st, 0),
    };
    // PER-SESSION-LIVESTATE (1.0.0.25): the other slot travels with the fanout so
    // an event for it is applied to it instead of being dropped.
    let (io, s, peer) = live.split2(slot);
    let mut fan = p1d::Fanout::new(s.host_id, slot, peer);
    let latched = p1d::take_event_err(s);
    if latched != 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "GET_FRAME: this session's ERROR event (errno={} ({})) was latched by the other session's pump -> failing this GET_FRAME",
            latched, -latched
        );
        io_log_line(line.as_str());
        return (map_error(virtio_media::Error::Errno(latched)), 0);
    }
    if s.pending_aus == 0 {
        io_log_line("GET_FRAME: no sent access unit");
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    let (inp, got) = match request_input(request, 0) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    let timeout_ms = if got >= 4 && !inp.is_null() {
        virtio_media::read_u32(core::slice::from_raw_parts(inp, got), 0)
    } else {
        15_000
    };
    let header_len = if tagged { size_of::<vmedia_abi::VM_FRAME_TAG_OUT>() } else { size_of::<vmedia_abi::VM_FRAME_INFO>() };
    let (outp, olen) = match request_output(request, header_len) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < header_len || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    if tagged {
        let tight = p1d::capture_row_bytes(&s.cfg).saturating_mul(s.cfg.height as usize).saturating_mul(3) / 2;
        if olen < header_len.saturating_add(tight) {
            io_log_line("GET_FRAME_TAG: output buffer lacks 48-byte tag header plus negotiated pixel capacity; rejected before dequeue");
            return (ST_BUFFER_TOO_SMALL, 0);
        }
    }
    let data = core::slice::from_raw_parts_mut(
        outp.add(header_len),
        olen - header_len,
    );
    let req = io.req_base();
    let resp = io.resp_base();
    match p1d::take_frame(
        &mut io.mmio,
        &mut io.q0,
        &req,
        &resp,
        &mut fan,
        &mut s.cfg,
        &mut s.frames,
        data,
        timeout_ms,
        &mut IoLog,
    ) {
        Ok(info) => {
            let total = header_len + info.Size as usize;
            if total > olen {
                return (ST_BUFFER_TOO_SMALL, 0);
            }
            ptr::write_unaligned(outp as *mut vmedia_abi::VM_FRAME_INFO, info);
            let tag = s.cfg.cap_tag[info.Index as usize];
            s.pending_aus = s.pending_aus.saturating_sub(1);
            if tagged {
                if tag == 0 { io_log_line("GET_FRAME_TAG: CAPTURE timestamp tag=0/invalid; frame consumed and requeued, no phantom pending AU"); return (ST_INVALID_PARAMETER, 0); }
                ptr::write_unaligned(outp as *mut vmedia_abi::VM_FRAME_TAG_OUT, vmedia_abi::VM_FRAME_TAG_OUT { Info: info, Tag: tag, SessionToken: s.token, Reserved0: 0 });
            }
            s.frames_got = s.frames_got.saturating_add(1);
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "GET_FRAME ok: frame {} ({}x{}, index {}, {} bytes), pending={}",
                s.frames_got, info.Width, info.Height, info.Index, info.Size, s.pending_aus
            );
            io_log_line(line.as_str());
            (ST_SUCCESS, total)
        }
        Err(e) => {
            // 1.0.0.12: a missing frame after a fire-and-forget SEND is most
            // likely the host refusing that QBUF; say so instead of leaving a
            // bare timeout in the log.  1.0.0.25: only this session's refusal.
            let errno = virtio_media::take_async_err(&mut io.q0, slot as u8);
            if errno != 0 {
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "GET_FRAME failed while an async QBUF of this session had answered errno={} ({})",
                    errno, -errno
                );
                io_log_line(line.as_str());
            }
            (map_error(e), 0)
        }
    }
}

/// P-BATCH ZEROCOPY (1.0.0.18): the mapped variant of `GET_FRAME`.
///
/// Blocks for the next decoded frame exactly like `GET_FRAME`, but instead of
/// copying the NV12 image into the output buffer it maps the capture buffer's
/// pool pages into the calling process and returns that VA.  The frame stays
/// checked out of the device until `VM_IOCTL_RELEASE_FRAME`, which is what makes
/// the in-place read safe: the host cannot decode into a buffer it does not own.
///
/// CONCURRENT-MAPPING (1.0.0.22): the mappings are a table keyed by capture
/// buffer index (see `p1d::MappingTable`).  A second MAP_FRAME is **not** a
/// protocol error any more -- that refusal is what forced every UMD into the
/// send/get/upload/release serial loop.  What is left is the physical limit:
/// a mapped buffer is checked out of the device, so at most `capture_count`
/// (REQBUFS grant, 18..20 for 1080p) can be out at once; asking for one more
/// while all are out is refused **before** the wait, with a log line that names
/// the number, instead of blocking for `timeout_ms` and answering err=110.
unsafe fn ioctl_map_frame(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    token: u32,
    hint: u32,
    tagged: bool,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): MAP_FRAME writes into the session's own
    // mapping table and checks a capture buffer out of *its* queue.  A replaced
    // client must never get a VA into the live session's pool ranges (the pixels
    // would be its frames, and the release would come from the wrong index
    // space).
    let slot = match unsafe { claim_session(live, owner, "MAP_FRAME", token, hint) } {
        Claim::Slot(i) => i,
        Claim::Refuse(st) => return (st, 0),
    };
    // PER-SESSION-LIVESTATE (1.0.0.25): same fanout as SEND/GET_FRAME -- a
    // completion for the other session is delivered to it, not dropped.
    let (io, s, peer) = live.split2(slot);
    let mut fan = p1d::Fanout::new(s.host_id, slot, peer);
    let latched = p1d::take_event_err(s);
    if latched != 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "MAP_FRAME: this session's ERROR event (errno={} ({})) was latched by the other session's pump -> failing this MAP_FRAME",
            latched, -latched
        );
        io_log_line(line.as_str());
        return (map_error(virtio_media::Error::Errno(latched)), 0);
    }
    if s.pending_aus == 0 {
        io_log_line("MAP_FRAME: no sent access unit");
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    // The pool is the concurrency limit.  `capture_count == 0` means the session
    // is not configured yet; `poll_frame` below reports that on its own.
    let capture_count = s.cfg.capture_count as usize;
    if capture_count != 0 && s.mappings.len() as usize >= capture_count {
        s.mappings.note_exhausted();
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "MAP_FRAME refused: all {} capture buffer(s) are mapped (live={}, high-water={}, exhausted={}) -> the caller must RELEASE_FRAME an index before it maps the next frame",
            capture_count,
            s.mappings.len(),
            s.mappings.high_water(),
            s.mappings.exhausted()
        );
        io_log_line(line.as_str());
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    let (inp, got) = match request_input(request, 0) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    let timeout_ms = if got >= 4 && !inp.is_null() {
        virtio_media::read_u32(core::slice::from_raw_parts(inp, got), 0)
    } else {
        15_000
    };
    let map_len = if tagged { size_of::<vmedia_abi::VM_FRAME_MAP_TAG_OUT>() } else { size_of::<vmedia_abi::VM_FRAME_MAP>() };
    let (outp, olen) = match request_output(request, map_len) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < map_len || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let req = io.req_base();
    let resp = io.resp_base();
    match p1d::map_frame(
        &mut io.mmio,
        &mut io.q0,
        &req,
        &resp,
        &mut fan,
        &mut s.cfg,
        &mut s.frames,
        io.pool_va,
        io.pool_pa,
        io.pool_len,
        timeout_ms,
        tagged,
        &mut IoLog,
    ) {
        Ok((m, info)) => {
            let tag = s.cfg.cap_tag[info.Index as usize];
            if tagged && tag == 0 {
                s.pending_aus = s.pending_aus.saturating_sub(1);
                io_log_line("MAP_FRAME_TAG: CAPTURE timestamp tag=0/invalid; frame consumed and requeued");
                p1d::unmap_frame(m);
                p1d::requeue_capture(&mut io.mmio, &mut io.q0, &req, &resp, s.host_id, &mut s.cfg, info.Index as usize, &mut IoLog);
                return (ST_INVALID_PARAMETER, 0);
            }
            let user_va = (m.va.as_ptr() as usize + m.delta as usize) as u64;
            let map = vmedia_abi::VM_FRAME_MAP {
                Width: info.Width,
                Height: info.Height,
                Stride: info.Stride,
                Size: info.Size,
                BytesUsed: info.BytesUsed,
                FourCC: info.FourCC,
                SessionId: info.SessionId,
                Index: info.Index,
                UserVa: user_va,
                MappedLength: m.len,
                Flags: 0,
            };
            // The buffer was dequeued by `map_frame`, so it counts as a fetched
            // frame whether or not the table accepts it below.
            s.pending_aus = s.pending_aus.saturating_sub(1);
            s.frames_got = s.frames_got.saturating_add(1);
            let here = unsafe { wdm::IoGetCurrentProcess() as usize };
            let entry = p1d::MappingEntry { frame: m, process: here, out: map };
            match s.mappings.insert(entry) {
                Ok(()) => {
                    ptr::write_unaligned(outp as *mut vmedia_abi::VM_FRAME_MAP, map);
                    if tagged { ptr::write_unaligned(outp as *mut vmedia_abi::VM_FRAME_MAP_TAG_OUT, vmedia_abi::VM_FRAME_MAP_TAG_OUT { Map: map, Tag: tag, SessionToken: s.token, Reserved0: 0 }); }
                    let mut line = virtio_media::LineBuf::new();
                    let _ = write!(
                        line,
                        "MAP_FRAME ok: frame {} ({}x{}, index {}, {} bytes) -> uva=0x{:X} len=0x{:X}, pending={}, mappings={}/{} high-water={}",
                        s.frames_got, info.Width, info.Height, info.Index, info.Size,
                        map.UserVa, map.MappedLength, s.pending_aus,
                        s.mappings.len(), s.cfg.capture_count,
                        s.mappings.high_water()
                    );
                    io_log_line(line.as_str());
                    (ST_SUCCESS, map_len)
                }
                Err((duplicate, entry)) => {
                    // Undo the window this call built.  The capture buffer is NOT
                    // requeued: the same index is still checked out from the
                    // earlier MAP_FRAME and that entry's RELEASE_FRAME is what
                    // puts it back (requeueing here would return a mapped buffer
                    // to the device while a client still reads it).
                    if entry.process == here {
                        p1d::unmap_frame(entry.frame);
                    } else {
                        drop(entry.frame);
                    }
                    if tagged { return (ST_INVALID_DEVICE_STATE, 0); }
                    if duplicate {
                        // Idempotent answer: the same index is already mapped, so
                        // hand back the mapping that is already out.
                        let existing = s.mappings.get(info.Index).map(|e| e.out);
                        let mut line = virtio_media::LineBuf::new();
                        let _ = write!(
                            line,
                            "MAP_FRAME: index {} was already mapped -> replayed its mapping (duplicate #{}, mappings={}/{})",
                            info.Index, s.mappings.duplicates(),
                            s.mappings.len(), s.cfg.capture_count
                        );
                        io_log_line(line.as_str());
                        if let Some(existing) = existing {
                            ptr::write_unaligned(
                                outp as *mut vmedia_abi::VM_FRAME_MAP,
                                existing,
                            );
                            return (ST_SUCCESS, map_len);
                        }
                        // Cannot happen (insert only says "duplicate" when the
                        // slot is occupied), but never claim success without a map.
                        return (ST_INVALID_DEVICE_STATE, 0);
                    }
                    // Index outside the table: give the buffer straight back and
                    // say which index was impossible.
                    let req = io.req_base();
                    let resp = io.resp_base();
                    p1d::requeue_capture(
                        &mut io.mmio,
                        &mut io.q0,
                        &req,
                        &resp,
                        s.host_id,
                        &mut s.cfg,
                        info.Index as usize,
                        &mut IoLog,
                    );
                    let mut line = virtio_media::LineBuf::new();
                    let _ = write!(
                        line,
                        "MAP_FRAME: capture index {} is outside the mapping table (0..{}) -> buffer requeued, nothing mapped",
                        info.Index, p1d::MAX_CAPTURE_BUFS
                    );
                    io_log_line(line.as_str());
                    (ST_INVALID_PARAMETER, 0)
                }
            }
        }
        Err(e) => {
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(line, "MAP_FRAME failed: {} -> falling back to the staged path", e.text());
            io_log_line(line.as_str());
            (map_error(e), 0)
        }
    }
}

/// P-BATCH ZEROCOPY: unmap one frame `MAP_FRAME` returned and give its capture
/// buffer back to the device.
///
/// CONCURRENT-MAPPING (1.0.0.22): `Index` frees **exactly that** capture buffer,
/// so a client can have several frames mapped and hand each one back on its own.
/// `0xFFFFFFFF` keeps the old "whatever is mapped" meaning and now releases every
/// mapping of the session (the UMD's stray-release probe still uses it).  An
/// index that is not mapped answers `ST_INVALID_PARAMETER` (user mode err=87) and
/// an empty table answers `ST_INVALID_DEVICE_STATE` (err=22), so "you released
/// something that was never mapped" and "you released nothing at all" are
/// distinguishable in a log.
unsafe fn ioctl_release_frame(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    token: u32,
    hint: u32,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): **this is the dangerous one**.  RELEASE_FRAME
    // takes an index and re-queues that capture buffer, and two sessions use the
    // same index range (0..capture_count).  A release from a replaced session
    // that was served against the live session would hand a buffer that is still
    // mapped to the live client back to the device -- it then gets decoded into
    // while the client reads it.  So the token is checked before the index is
    // even looked at.
    let slot = match unsafe { claim_session(live, owner, "RELEASE_FRAME", token, hint) } {
        Claim::Slot(i) => i,
        Claim::Refuse(st) => return (st, 0),
    };
    let (io, s) = live.split(slot);
    let (inp, got) = match request_input(request, 0) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    let _ = in_len;
    let index = if got >= 8 && !inp.is_null() {
        virtio_media::read_u32(core::slice::from_raw_parts(inp, got), 4)
    } else {
        vmedia_abi::VM_RELEASE_ALL_INDEX
    };
    if s.mappings.is_empty() {
        s.mappings.note_unknown_release();
        io_log_line("RELEASE_FRAME: nothing is mapped");
        return (ST_INVALID_DEVICE_STATE, 0);
    }
    let here = unsafe { wdm::IoGetCurrentProcess() as usize };
    if index == vmedia_abi::VM_RELEASE_ALL_INDEX {
        // Backward compatible "whatever is mapped" = release the whole table.
        // The returned indices are exactly the capture buffers that were out, so
        // each one is requeued once (the old single-slot code requeued the one it
        // held; a client that only ever maps one frame sees the same behaviour).
        let released = unsafe { s.mappings.release_all(here) };
        let requeued = if s.open {
            let req = io.req_base();
            let resp = io.resp_base();
            for i in 0..released.count {
                p1d::requeue_capture(
                    &mut io.mmio,
                    &mut io.q0,
                    &req,
                    &resp,
                    s.host_id,
                    &mut s.cfg,
                    released.indices[i] as usize,
                    &mut IoLog,
                );
            }
            released.count
        } else {
            0
        };
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "RELEASE_FRAME ok: released all {} mapping(s) ({} unmapped here, {} foreign process), {} requeued, live=0 unknown_releases={}",
            released.count, released.unmapped, released.foreign, requeued,
            s.mappings.unknown_releases()
        );
        io_log_line(line.as_str());
        return (ST_SUCCESS, 0);
    }
    let Some(entry) = s.mappings.take(index) else {
        // A different, explicit error than "nothing is mapped": the index is
        // either out of range or was already released (a UMD bug or a stale
        // index), and saying which index keeps it out of the "the session is
        // broken" bucket.
        s.mappings.note_unknown_release();
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "RELEASE_FRAME: index {} is not mapped (live={}, unknown_releases={}) -> nothing requeued",
            index,
            s.mappings.len(),
            s.mappings.unknown_releases()
        );
        io_log_line(line.as_str());
        return (ST_INVALID_PARAMETER, 0);
    };
    let mapped_index = entry.frame.index;
    let len = entry.frame.len;
    if entry.process == here {
        p1d::unmap_frame(entry.frame);
    } else {
        // A different process cannot unmap another address space's VA.  Drop the
        // MDL and leave the (read-only) VA to that process's teardown.
        io_log_line("RELEASE_FRAME: called from another process; MDL freed, VA left behind");
        drop(entry.frame);
    }
    // Give the buffer back to the device (the QBUF GET_FRAME used to do).
    let req = io.req_base();
    let resp = io.resp_base();
    p1d::requeue_capture(
        &mut io.mmio,
        &mut io.q0,
        &req,
        &resp,
        s.host_id,
        &mut s.cfg,
        mapped_index as usize,
        &mut IoLog,
    );
    let mut line = virtio_media::LineBuf::new();
    let _ = write!(
        line,
        "RELEASE_FRAME ok: index {} ({} bytes) requeued, mappings={}/{} high-water={}",
        mapped_index, len, s.mappings.len(), s.cfg.capture_count,
        s.mappings.high_water()
    );
    io_log_line(line.as_str());
    (ST_SUCCESS, 0)
}

/// CONCURRENT-MAPPING (1.0.0.22): take the whole mapping table down and log what
/// it took.  Used by every path that ends or replaces a session (CLOSE, FLUSH,
/// OPEN-over-a-stale-session).  No capture buffer is requeued here: the caller
/// runs this only when the host session -- and with it the capture queue -- is
/// about to disappear, so a QBUF would be sent into a dying session.  A mapping
/// owned by another address space can only lose its MDL; it is counted so a
/// cross-process client becomes visible in the log.
///
/// SESSION-OWNERSHIP (1.0.0.24): takes **one session**, not the device, so a
/// CLOSE can only ever drop the mappings of the session that owns it.
unsafe fn drain_mappings(s: &mut SessionSlot, why: &str) -> p1d::ReleasedMappings {
    let here = unsafe { wdm::IoGetCurrentProcess() as usize };
    let live_now = s.mappings.len();
    let high = s.mappings.high_water();
    let released = unsafe { s.mappings.release_all(here) };
    if released.count != 0 {
        let mut line = virtio_media::LineBuf::new();
        let _ = write!(
            line,
            "{}: token {} released {} of {} live mapping(s) ({} unmapped here, {} foreign process, high-water {})",
            why, s.token, released.count, live_now, released.unmapped, released.foreign, high
        );
        io_log_line(line.as_str());
    }
    released
}

unsafe fn ioctl_close(
    request: wdf::WDFREQUEST,
    in_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    token: u32,
    hint: u32,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): **this function used to be the bug.**
    // 1.0.0.23 cleared `session_open`/`session_id`/`cfg`/`mappings` whatever the
    // request said, so a replaced decoder's CLOSE destroyed the session that had
    // replaced it: the new session's next SEND answered ST_INVALID_DEVICE_STATE
    // (0xC0000184 -> user mode err=22) and Chromium's decoder failed
    // (D3DStatus::6 kDecoderFailedDecode).
    //
    // The rule now: only the owner may close.  A CLOSE that names a session that
    // is no longer live is **ignored** -- success, one log line, nothing touched.
    // It is deliberately not an error: it arrives from a teardown path in the
    // *old* client, and failing it would only add a second bogus failure to a
    // client that is already going away.
    let slot = match owner {
        p1d::Owner::Live(i) => i,
        p1d::Owner::Legacy(i) => {
            live.legacy_requests = live.legacy_requests.saturating_add(1);
            live.sessions[i].legacy_requests = live.sessions[i].legacy_requests.saturating_add(1);
            if live.sessions[i].legacy_requests <= 3 {
                let mut line = virtio_media::LineBuf::new();
                let _ = write!(
                    line,
                    "CLOSE: legacy request without a session token{} -> token {} (only session open)",
                    if hint != 0 { " (host-id hint matched)" } else { "" },
                    live.sessions[i].token
                );
                io_log_line(line.as_str());
            }
            i
        }
        p1d::Owner::Stale => {
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "CLOSE: session {} is not the live session (live: {}) -> IGNORED, nothing torn down",
                token_or_hint(token, hint),
                live_session_summary(live).as_str()
            );
            io_log_line(line.as_str());
            return (ST_SUCCESS, 0);
        }
        p1d::Owner::Ambiguous => {
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "CLOSE: legacy request without a session token while {} sessions are open (live: {}) -> IGNORED (cannot be attributed)",
                live.open_sessions(),
                live_session_summary(live).as_str()
            );
            io_log_line(line.as_str());
            return (ST_SUCCESS, 0);
        }
        p1d::Owner::NoSession => {
            io_log_line("CLOSE: no session open (nothing to do)");
            return (ST_SUCCESS, 0);
        }
    };
    let device = live.io.mmio.wdf_device;
    let (io, s) = live.split(slot);
    // CONCURRENT-MAPPING: nothing may stay mapped across a CLOSE, and this runs
    // before `close_session` for the same reason it always did -- a mapped
    // buffer would keep its capture buffer out of the queue being torn down.
    let _ = unsafe { drain_mappings(s, "CLOSE") };
    let (inp, got) = match request_input(request, 0) {
        Ok(v) => v,
        Err(_) => (ptr::null_mut(), 0),
    };
    let _ = in_len;
    // The host id comes from the *slot*, not from the request: a legacy client
    // may echo anything, and the slot is the authority on which host session
    // this generation owns.
    let session_id = s.host_id;
    let token_closed = s.token;
    let _ = (inp, got);
    let req = io.req_base();
    let resp = io.resp_base();
    let result = p1d::close_session(
        &mut io.mmio,
        &mut io.q0,
        &req,
        &resp,
        session_id,
        &mut s.cfg,
        4000,
        &mut IoLog,
    );
    // P2-2f: whatever the device answers, the guest forgets the session.  In
    // 1.0.0.7 a refused CLOSE returned early and left session_open set, so the
    // next OPEN failed with ST_INVALID_DEVICE_STATE (err 22 in user mode) until
    // the device was restarted -- the exact P2-2e wedge.
    let aus_sent = s.aus_sent;
    let frames_got = s.frames_got;
    // `clear()` keeps the token (so a *later* CLOSE with the same token is
    // recognised as "already closed" rather than "never existed") but drops the
    // host id and the whole cfg -- see the ownership rule in `resolve`.
    s.open = false;
    s.host_id = 0;
    s.pending_aus = 0;
    s.frames = p1d::PendingFrames::empty();
    s.cfg = SessionConfig::empty();
    // PER-SESSION-LIVESTATE (1.0.0.25): this slot's latched error state goes with
    // the session.  A stale async errno owned by this slot must not be inherited
    // by the next session that reuses it, and a routed ERROR event that was
    // waiting for this session is meaningless now.
    virtio_media::clear_async_err(&mut io.q0, slot as u8);
    s.event_err = 0;
    let mut line = virtio_media::LineBuf::new();
    match result {
        Ok(()) => {
            live.closes = live.closes.saturating_add(1);
            let _ = write!(
                line,
                "CLOSE: token {} (host session {}) closed: {} AU sent / {} frame decoded (opens={} closes={} failed_closes={} stale_closes={} open_sessions={})",
                token_closed, session_id, aus_sent, frames_got,
                live.opens, live.closes, live.failed_closes, live.stale_closes,
                live.open_sessions()
            );
            io_log_line(line.as_str());
        }
        Err(e) => {
            live.failed_closes = live.failed_closes.saturating_add(1);
            let status = map_error(e);
            let _ = write!(
                line,
                "CLOSE: device refused token {} (host session {}, NTSTATUS 0x{:08X}) -> guest state cleared anyway (opens={} closes={} failed_closes={})",
                token_closed, session_id, status, live.opens, live.closes, live.failed_closes
            );
            io_log_line(line.as_str());
        }
    }
    // P-BATCH MSI-X: per-session interrupt evidence (irqs/work/waits/wakeups/
    // timeouts/fallbacks) so a CLOSE line shows whether the decode was actually
    // interrupt-driven.
    irq::log_summary(device, "CLOSE");
    (ST_SUCCESS, 0)
}

/// P3-2 / 1.0.0.11: flush = drop the queued access units and undelivered frames
/// and give the client a brand-new host session.
///
/// The old session is closed (its pool ranges MUNMAP'd) and a fresh one opened,
/// so the decoder loses every reference frame.  The first SEND after a flush
/// finds `cfg.configured == false` and runs the full `configure_and_send`
/// sequence again: that is exactly the "next AU starts from an IDR" contract
/// (the UMD injects SPS/PPS into that AU).  The IOCTL answers with the new
/// session id plus the drop counters, and logs the one line the bring-up
/// relies on: `FLUSH: dropped N AU / M frames`.
unsafe fn ioctl_flush(
    request: wdf::WDFREQUEST,
    in_len: usize,
    out_len: usize,
    live: &mut LiveState,
    owner: p1d::Owner,
    token: u32,
    hint: u32,
) -> (u32, usize) {
    // SESSION-OWNERSHIP (1.0.0.24): only the owner may flush, and the flush
    // **bumps the generation**: the answer carries the new token, the old one is
    // dead from that moment.  That is what makes "flush / seek / rebuild" safe
    // against a completion still in flight for the old generation -- it comes
    // back with a token the driver no longer accepts, so it can never write the
    // new session's buffers (which are different pool ranges entirely).
    let slot = match unsafe { claim_session(live, owner, "FLUSH", token, hint) } {
        Claim::Slot(i) => i,
        Claim::Refuse(st) => return (st, 0),
    };
    let (io, s) = live.split(slot);
    let old_token = s.token;
    let old_id = s.host_id;
    // CONCURRENT-MAPPING (1.0.0.22): the flush replaces the whole capture queue
    // with a new session, so every mapping of the old one is unmapped first (no
    // requeue -- the buffers stop existing with the session).  A mapping left
    // behind would describe pool ranges the new session is about to re-map.
    let _ = unsafe { drain_mappings(s, "FLUSH") };
    let (outp, olen) = match request_output(request, size_of::<vmedia_abi::VM_FLUSH_OUT>()) {
        Ok(v) => v,
        Err(st) => return (st, 0),
    };
    if olen < size_of::<vmedia_abi::VM_FLUSH_OUT>() || out_len < olen {
        return (ST_BUFFER_TOO_SMALL, 0);
    }
    let _ = (in_len, token, hint);
    // An AU that was queued but never answered by GET_FRAME is dropped; a
    // decoded frame the client never picked up is dropped too (it belongs to
    // the old sequence and would be presented at the wrong PTS after a seek).
    let dropped_au = s.cfg.aus_queued.min(u32::MAX as u64) as u32;
    let dropped_frames = s.pending_aus;
    let req = io.req_base();
    let resp = io.resp_base();
    let flushed = p1d::flush_session(
        &mut io.mmio,
        &mut io.q0,
        &req,
        &resp,
        old_id,
        &mut s.cfg,
        &mut IoLog,
    );
    match flushed {
        Ok(new_id) => {
            // The replacement session is a new generation.  `alloc_token` is
            // called through the raw `live` pointer's field: the split borrow of
            // `io`/`s` ended with the `flush_session` call above.
            let new_token = live.alloc_token();
            {
                let s = &mut live.sessions[slot];
                s.token = new_token;
                s.host_id = new_id;
                s.cfg = SessionConfig::empty();
                s.pending_aus = 0;
                s.frames = p1d::PendingFrames::empty();
                s.aus_sent = 0;
                s.frames_got = 0;
            }
            let out = vmedia_abi::VM_FLUSH_OUT {
                SessionId: new_id,
                DroppedAu: dropped_au,
                DroppedFrames: dropped_frames,
                SessionToken: new_token,
            };
            ptr::write_unaligned(outp as *mut vmedia_abi::VM_FLUSH_OUT, out);
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "FLUSH: dropped {} AU / {} frames; token {} (host {}) -> token {} (host {}) (configured=0, next SEND restarts from an IDR)",
                dropped_au, dropped_frames, old_token, old_id, new_token, new_id
            );
            io_log_line(line.as_str());
            (ST_SUCCESS, size_of::<vmedia_abi::VM_FLUSH_OUT>())
        }
        Err(e) => {
            // The old session is gone either way; forget it so the next OPEN/SEND
            // can bring up a new one (no wedged ST_INVALID_DEVICE_STATE).
            {
                let s = &mut live.sessions[slot];
                s.open = false;
                s.host_id = 0;
                s.pending_aus = 0;
                s.frames = p1d::PendingFrames::empty();
                s.cfg = SessionConfig::empty();
            }
            let status = map_error(e);
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "FLUSH: dropped {} AU / {} frames but the fresh session failed (NTSTATUS 0x{:08X}) -> token {} cleared, next OPEN starts over",
                dropped_au, dropped_frames, status, old_token
            );
            io_log_line(line.as_str());
            (status, 0)
        }
    }
}

unsafe extern "C" fn evt_io_device_control(
    queue: wdf::WDFQUEUE,
    request: wdf::WDFREQUEST,
    output_buffer_length: usize,
    input_buffer_length: usize,
    io_control_code: u32,
) {
    let device = wdf_io_queue_get_device(queue);
    // P3/1.0.0.10: a streaming session does two IOCTLs per frame, so the generic
    // per-IOCTL head/tail lines are only logged for the first few and for
    // OPEN/CLOSE; the per-frame lines in SEND/GET_FRAME carry the evidence.
    let tick = IOCTL_TICK.fetch_add(1, Ordering::Relaxed);
    let verbose = tick < 8
        || io_control_code == vmedia_abi::VM_IOCTL_OPEN
        || io_control_code == vmedia_abi::VM_IOCTL_CLOSE
        || io_control_code == vmedia_abi::VM_IOCTL_FLUSH;
    if verbose {
        let mut head = virtio_media::LineBuf::new();
        let _ = write!(
            head,
            "IOCTL code=0x{:08X} in={} out={}",
            io_control_code, input_buffer_length, output_buffer_length
        );
        io_log_line(head.as_str());
    }
    let (status, information) = handle_ioctl(
        device,
        request,
        output_buffer_length,
        input_buffer_length,
        io_control_code,
    );
    if verbose || status != ST_SUCCESS {
        let mut tail = virtio_media::LineBuf::new();
        let _ = write!(tail, "IOCTL 0x{:08X} -> NTSTATUS 0x{:08X} info={}", io_control_code, status, information);
        io_log_line(tail.as_str());
    }
    let force = io_control_code == vmedia_abi::VM_IOCTL_OPEN
        || io_control_code == vmedia_abi::VM_IOCTL_CLOSE
        || io_control_code == vmedia_abi::VM_IOCTL_FLUSH
        || status != ST_SUCCESS;
    io_log_flush(device, force);
    wdf_request_complete(request, status, information);
}

unsafe extern "C" fn evt_prepare_hardware(
    device: wdf::WDFDEVICE,
    resources_raw: wdf::WDFCMRESLIST,
    resources_translated: wdf::WDFCMRESLIST,
) -> u32 {
    let mut log = KernelLog::new();
    let mut buf = [0u8; 260];
    let n = query_ascii_property(device, wdf::DEVICE_REGISTRY_PROPERTY::DevicePropertyHardwareID, &mut buf);

    if n > 0 && ascii_starts_with(&buf[..n], b"ACPI") {
        let mut inst = [0u8; 260];
        let m = unsafe { query_instance_id(device, &mut inst) };
        if m > 0 && !ascii_ends_with_ci(&inst[..m], b"\\MEDIA_HOST") {
            vlog(&mut log, format_args!("=== ACPI pool is not MEDIA_HOST; no pool stored ==="));
            log.finish(device);
            return STATUS::SUCCESS.to_u32();
        }
        vlog(&mut log, format_args!("=== EvtDevicePrepareHardware (P2-1: ACPI media_host pool) ==="));
        let result = unsafe { prepare_pool(resources_translated, &mut log) };
        match &result {
            Ok(()) => vlog(&mut log, format_args!("=== media_host pool provider OK ===")),
            Err(e) => vlog(&mut log, format_args!("=== media_host pool provider FAILED: {} ===", e.text())),
        }
        log.finish(device);
        return match result {
            Ok(()) => STATUS::SUCCESS.to_u32(),
            Err(_) => STATUS::UNSUCCESSFUL.to_u32(),
        };
    }

    vlog(
        &mut log,
        format_args!(
            "=== EvtDevicePrepareHardware (P2-1 {}: virtio-media IOCTL session) ===",
            DRIVER_VERSION
        ),
    );
    let result = unsafe { Probe { log: &mut log }.run(device, resources_raw, resources_translated) };
    match &result {
        // Probe::run logs the decoder/encoder outcome as its last line.
        Ok(()) => {}
        Err(e) => match *e {
            virtio_media::Error::IoctlFailed(code, errno) => vlog(
                &mut log,
                format_args!(
                    "=== probe FAILED: ioctl={} errno={} ({}) (0x{:?}) ===",
                    code, errno, -errno, e
                ),
            ),
            virtio_media::Error::Errno(errno) => vlog(
                &mut log,
                format_args!("=== probe FAILED: errno={} ({}) (0x{:?}) ===", errno, -errno, e),
            ),
            _ => vlog(&mut log, format_args!("=== probe FAILED: {} (0x{:?}) ===", e.text(), e)),
        },
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
    // PnP callbacks are not covered by I/O automatic synchronization. Share
    // the passive device callback lock with file cleanup and request handlers.
    let Some(acquire)=wdf_table_fn!(wdf::PFN_WDFOBJECTACQUIRELOCK,WdfObjectAcquireLockTableIndex)else{return ST_INVALID_DEVICE_REQUEST};
    let Some(release)=wdf_table_fn!(wdf::PFN_WDFOBJECTRELEASELOCK,WdfObjectReleaseLockTableIndex)else{return ST_INVALID_DEVICE_REQUEST};
    acquire(wdf::WdfDriverGlobals,device as wdf::WDFOBJECT);
    // The live session and BAR mappings remain valid until cleanup is excluded.
    if let Some(idx) = unsafe { slot_lookup(device) } {
        let mut log = KernelLog::new();
        // P-BATCH MSI-X: tear the interrupt down *first*, so the CLOSE/MUNMAP in
        // LiveState::drop runs with `armed = 0` (pure polling) instead of
        // blocking on an interrupt object that is about to disappear.
        unsafe { irq::release(device, &mut log) };
        let n = unsafe { slot_take(idx, &mut log) };
        vlog(
            &mut log,
            format_args!("=== EvtDeviceReleaseHardware: released {} mapped memory BAR(s) ===", n),
        );
    }
    release(wdf::WdfDriverGlobals,device as wdf::WDFOBJECT);
    STATUS::SUCCESS.to_u32()
}

unsafe extern "C" fn evt_file_cleanup(file:wdf::WDFFILEOBJECT){
    let Some(get_device)=wdf_table_fn!(wdf::PFN_WDFFILEOBJECTGETDEVICE,WdfFileObjectGetDeviceTableIndex)else{return};
    let device=get_device(wdf::WdfDriverGlobals,file);
    let Some(acquire)=wdf_table_fn!(wdf::PFN_WDFOBJECTACQUIRELOCK,WdfObjectAcquireLockTableIndex)else{return};
    let Some(release)=wdf_table_fn!(wdf::PFN_WDFOBJECTRELEASELOCK,WdfObjectReleaseLockTableIndex)else{return};
    // File objects must use ScopeNone; explicitly share the passive device
    // callback lock with the sequential queue and ReleaseHardware.
    acquire(wdf::WdfDriverGlobals,device as wdf::WDFOBJECT);
    if let Some(idx)=slot_lookup(device){
        let live=(*(ptr::addr_of!(SLOTS) as *const DevSlot).add(idx)).live;
        if !live.is_null(){
            let live=&mut *live;
            if !live.is_decoder&&live.encoder.owns_file(file as usize){
                let token=live.encoder.token;
                io_log_line("encoder file cleanup: reclaiming token-owned session");
                let _=close_encoder_owner(live,token);
                if let Some(events)=live.io.mmio.events.as_mut(){events.sync_owners(&live.sessions,live.encoder);}
            }
        }
    }
    release(wdf::WdfDriverGlobals,device as wdf::WDFOBJECT);
}

unsafe extern "C" fn evt_driver_device_add(_driver: wdf::WDFDRIVER, mut device_init: wdf::PWDFDEVICE_INIT) -> u32 {
    dbg_line(b"EvtDeviceAdd: claiming a virtio-media function or the media_host pool");

    let mut pnp: wdf::WDF_PNPPOWER_EVENT_CALLBACKS = zeroed();
    pnp.Size = size_of::<wdf::WDF_PNPPOWER_EVENT_CALLBACKS>() as u32;
    pnp.EvtDevicePrepareHardware = Some(evt_prepare_hardware);
    pnp.EvtDeviceReleaseHardware = Some(evt_release_hardware);
    wdf_device_init_set_pnp_callbacks(device_init, &mut pnp);

    let Some(set_file)=wdf_table_fn!(wdf::PFN_WDFDEVICEINITSETFILEOBJECTCONFIG,WdfDeviceInitSetFileObjectConfigTableIndex)else{return ST_INVALID_DEVICE_REQUEST};
    let mut file_config:wdf::WDF_FILEOBJECT_CONFIG=zeroed();
    file_config.Size=size_of::<wdf::WDF_FILEOBJECT_CONFIG>() as u32;
    file_config.EvtFileCleanup=Some(evt_file_cleanup);
    file_config.AutoForwardCleanupClose=wdf::WDF_TRI_STATE::WdfFalse;
    file_config.FileObjectClass=wdf::WDF_FILEOBJECT_CLASS::WdfFileObjectWdfCannotUseFsContexts;
    let mut file_attrs:wdf::WDF_OBJECT_ATTRIBUTES=zeroed();
    file_attrs.Size=size_of::<wdf::WDF_OBJECT_ATTRIBUTES>() as u32;
    file_attrs.ExecutionLevel=wdf::WDF_EXECUTION_LEVEL::WdfExecutionLevelPassive;
    file_attrs.SynchronizationScope=wdf::WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeNone;
    set_file(wdf::WdfDriverGlobals,device_init,&mut file_config,&mut file_attrs);
    let mut attrs:wdf::WDF_OBJECT_ATTRIBUTES=zeroed();
    attrs.Size=size_of::<wdf::WDF_OBJECT_ATTRIBUTES>() as u32;
    attrs.ExecutionLevel=wdf::WDF_EXECUTION_LEVEL::WdfExecutionLevelPassive;
    attrs.SynchronizationScope=wdf::WDF_SYNCHRONIZATION_SCOPE::WdfSynchronizationScopeDevice;
    let mut device: wdf::WDFDEVICE = ptr::null_mut();
    if let Err(status) = wdf_device_create(&mut device_init, &mut device, &mut attrs) {
        dbg_line(b"WdfDeviceCreate failed");
        return status.to_u32();
    }

    let mut buf = [0u8; 260];
    let n = query_ascii_property(device, wdf::DEVICE_REGISTRY_PROPERTY::DevicePropertyHardwareID, &mut buf);
    if n == 0 {
        dbg_line(b"WARNING: hardware id query failed");
        return STATUS::UNSUCCESSFUL.to_u32();
    }
    let mut line = [0u8; 192];
    let mut k = 0;
    for &b in b"hardware id: ".iter().chain(buf[..n].iter()) {
        if k < line.len() - 1 {
            line[k] = b;
            k += 1;
        }
    }
    dbg_line(&line[..k]);

    if ascii_starts_with(&buf[..n], b"ACPI") {
        let mut inst = [0u8; 260];
        let m = query_instance_id(device, &mut inst);
        if m > 0 {
            let mut line = [0u8; 192];
            let mut k = 0;
            for &b in b"instance id: ".iter().chain(inst[..m].iter()) {
                if k < line.len() - 1 {
                    line[k] = b;
                    k += 1;
                }
            }
            dbg_line(&line[..k]);
        }
        // DRVM0001 is shared by every pool (gpu_guest, venus_host, drm2kgsl,
        // media_host). Only media_host is ours; the others stay with the
        // provider driver (or failed, as they were before this package).
        if m > 0 && !ascii_ends_with_ci(&inst[..m], b"\\MEDIA_HOST") {
            dbg_line(b"ACPI pool is not MEDIA_HOST; bound but idle");
            return STATUS::SUCCESS.to_u32();
        }
        dbg_line(b"bound ACPI DRVM0001\\MEDIA_HOST (media_host pool)");
        return STATUS::SUCCESS.to_u32();
    }

    if ascii_starts_with(&buf[..n], b"PCI\\VEN_1AF4&DEV_1070") {
        set_friendly_name(device);
        // The interface GUID is the documented discovery mechanism; the
        // per-card symbolic link is created in PrepareHardware, once the
        // device config has told us decoder vs encoder.
        let _ = unsafe { create_device_interface(device) };
        let _ = unsafe { create_io_queue(device) };
        // P-BATCH MSI-X: the interrupt object is created here (the canonical
        // KMDF place, PASSIVE_LEVEL) and armed in EvtDevicePrepareHardware once
        // the raw resource list has said which MSI-X table entry to use. A
        // failure is not fatal: the transport then polls like 1.0.0.16.
        let irq_status = unsafe { irq::create(device) };
        if irq_status == ST_SUCCESS {
            dbg_line(b"interrupt object created (MSI-X message limit = 1)");
        } else {
            dbg_line(b"WARNING: WdfInterruptCreate failed; the transport will poll");
        }
        dbg_line(b"device id 0x1070 (VIRTIO_ID_MEDIA) matched");
        return STATUS::SUCCESS.to_u32();
    }

    dbg_line(b"WARNING: hardware id is not a virtio-media function");
    STATUS::UNSUCCESSFUL.to_u32()
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DriverEntry(driver: wdf::PDRIVER_OBJECT, registry_path: wdf::PCUNICODE_STRING) -> u32 {
    dbg_line(b"DriverEntry (virtio-media P2-1, IOCTL session API)");

    // Guards the per-device mapping slots (two virtio-media functions can start
    // back to back) and the IOCTL log ring.
    unsafe {
        wdm::KeInitializeSpinLock(ptr::addr_of_mut!(SLOTS_LOCK));
        wdm::KeInitializeSpinLock(ptr::addr_of_mut!(IOLOG_LOCK));
    }

    let mut config: wdf::WDF_DRIVER_CONFIG = zeroed();
    config.Size = size_of::<wdf::WDF_DRIVER_CONFIG>() as u32;
    config.EvtDriverDeviceAdd = Some(evt_driver_device_add);

    ntstatus(wdf::WdfDriverCreate(driver, registry_path, ptr::null_mut(), &mut config))
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { wdm::KeBugCheck(0xDEAD_DEAD) }
}
