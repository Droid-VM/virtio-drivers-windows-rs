//! platform-independent virtio-media (virtio 1.x, modern PCI) bring-up.
//!
//! P1c-3: this file no longer contains any PCI configuration-space code. The
//! caller maps the MMIO BARs that the PnP manager hands out in the translated
//! resource list and locates the four virtio structures by probing the BAR
//! (see `Caps::single_bar_layout`). [`Mmio`] is the only platform hook; the
//! vring lives in guest RAM and is accessed through the raw addresses in
//! [`Queue`].
//!
//! Protocol references (crosvm checkout):
//!   * `virtio_sys/src/virtio_ids.rs:21`            VIRTIO_ID_MEDIA = 48
//!   * `devices/src/virtio/device_constants.rs:161` QUEUE_SIZES = [256, 256]
//!   * `devices/src/virtio/virtio_pci_device.rs:255-282` common/isr/device/notify
//!     offsets inside the settings BAR (0x0 / 0x1000 / 0x2000 / 0x3000)
//!   * `virtio-media-0.0.7/src/protocol.rs`         command/response structs
//!   * `virtio-media-0.0.7/src/lib.rs:262-378`      VirtioMediaDeviceRunner

use core::fmt::{self, Write as _};
use core::ptr;
use core::sync::atomic::{fence, Ordering};

pub const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
pub const VIRTIO_PCI_MEDIA_DEVICE_ID: u16 = 0x1070;

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
pub const VIRTIO_RING_F_EVENT_IDX: u64 = 1 << 29;
pub const VIRTIO_F_SUSPEND: u64 = 1 << 35;

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// Virtio-PCI structure offsets inside the settings BAR. Both crosvm
// (`virtio_pci_device.rs:255-266`) and QEMU place the four structures at these
// page offsets; P1c-3 has no PCI config space access, so the layout is probed
// and then these relative offsets are used.
pub const LAYOUT_ISR_OFFSET: u32 = 0x1000;
pub const LAYOUT_DEVICE_OFFSET: u32 = 0x2000;
pub const LAYOUT_NOTIFY_OFFSET: u32 = 0x3000;
pub const LAYOUT_COMMON_SIZE: u32 = 0x38;
pub const LAYOUT_BAR_MIN: u32 = 0x4000;
pub const NOTIFY_OFF_MULTIPLIER_DEFAULT: u32 = 4;

// virtio_pci_common_cfg register offsets (virtio 1.x 4.1.4.3)
const COMMON_DEVICE_FEATURE_SELECT: u32 = 0x00;
const COMMON_DEVICE_FEATURE: u32 = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: u32 = 0x08;
const COMMON_DRIVER_FEATURE: u32 = 0x0c;
const COMMON_MSIX_CONFIG: u32 = 0x10;
const COMMON_NUM_QUEUES: u32 = 0x12;
const COMMON_DEVICE_STATUS: u32 = 0x14;
const COMMON_CONFIG_GENERATION: u32 = 0x15;
const COMMON_QUEUE_SELECT: u32 = 0x16;
const COMMON_QUEUE_SIZE: u32 = 0x18;
const COMMON_QUEUE_MSIX_VECTOR: u32 = 0x1a;
const COMMON_QUEUE_ENABLE: u32 = 0x1c;
const COMMON_QUEUE_NOTIFY_OFF: u32 = 0x1e;
const COMMON_QUEUE_DESC: u32 = 0x20;
const COMMON_QUEUE_DRIVER: u32 = 0x28;
const COMMON_QUEUE_DEVICE: u32 = 0x30;

pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2;
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;

pub const QUEUE_COMMAND: u16 = 0;
pub const QUEUE_EVENT: u16 = 1;
pub const QUEUE_DEPTH: u16 = 256;

pub const MEDIA_CMD_OPEN: u32 = 1;
pub const MEDIA_CMD_CLOSE: u32 = 2;
pub const MEDIA_CMD_IOCTL: u32 = 3;
pub const V4L2_IOCTL_QUERYCAP: u32 = 0;
pub const V4L2_IOCTL_ENUM_FMT: u32 = 2;
pub const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
pub const V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoMemoryResources,
    MapFailed(u8),
    NoCommonConfig,
    NoNotifyRegion,
    BarTooSmall(u8),
    MissingRegion(&'static str),
    BadBar(u8),
    ResetTimeout(u8),
    VersionOneMissing(u64),
    FeaturesOkRejected(u8),
    QueueTooSmall(u16),
    QueueNotReady(u16, u16),
    QueueMemorySmall(usize, usize),
    UsedId(u32),
    ResponseTimeout(u16, u16, u16),
    DeviceStatus(u8),
}

impl Error {
    pub fn text(self) -> &'static str {
        match self {
            Error::NoMemoryResources => "translated resource list has no memory BAR",
            Error::MapFailed(_) => "MmMapIoSpaceEx failed for a memory BAR",
            Error::NoCommonConfig => "no virtio common config found in the mapped BARs",
            Error::NoNotifyRegion => "notify region does not fit in the mapped BAR",
            Error::BarTooSmall(_) => "memory BAR is too small for the virtio layout",
            Error::MissingRegion(_) => "required virtio PCI region missing",
            Error::BadBar(_) => "virtio region is outside its mapped BAR",
            Error::ResetTimeout(_) => "device did not return to status 0 after reset",
            Error::VersionOneMissing(_) => "device does not offer VIRTIO_F_VERSION_1",
            Error::FeaturesOkRejected(_) => "device cleared FEATURES_OK",
            Error::QueueTooSmall(_) => "device queue is smaller than 8 entries",
            Error::QueueNotReady(_, _) => "queue_enable did not read back as 1",
            Error::QueueMemorySmall(_, _) => "vring buffer too small",
            Error::UsedId(_) => "used ring returned an unexpected descriptor head",
            Error::ResponseTimeout(_, _, _) => "no used-ring entry before the timeout",
            Error::DeviceStatus(_) => "unexpected device status",
        }
    }
}

pub trait Log {
    fn line(&mut self, s: &str);
}

impl<F: FnMut(&str)> Log for F {
    fn line(&mut self, s: &str) {
        self(s);
    }
}

pub struct LineBuf {
    buf: [u8; 320],
    len: usize,
}

impl LineBuf {
    pub const fn new() -> Self {
        Self { buf: [0u8; 320], len: 0 }
    }
    pub fn as_str(&self) -> &str {
        // Only ASCII format strings and ASCII card names are written here.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = core::cmp::min(s.len(), self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

pub fn log_args(log: &mut dyn Log, args: fmt::Arguments<'_>) {
    let mut b = LineBuf::new();
    let _ = b.write_fmt(args);
    log.line(b.as_str());
}

macro_rules! vlog {
    ($log:expr, $($arg:tt)*) => {
        $crate::virtio_media::log_args($log, format_args!($($arg)*))
    };
}

/// One virtio PCI structure (common / notify / ISR / device config).
///
/// `bar` is the index into the caller's list of mapped memory resources, not a
/// raw PCI BAR number: P1c-3 never reads the PCI BAR registers.
#[derive(Clone, Copy, Default)]
pub struct Region {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    pub cap_offset: u8,
    pub id: u8,
    pub present: bool,
}

pub struct Caps {
    pub common: Region,
    pub notify: Region,
    pub isr: Option<Region>,
    pub device: Option<Region>,
    pub shm: Option<Region>,
    pub notify_off_multiplier: u32,
}

impl Caps {
    /// Build the cap table for the layout virtio uses when every structure
    /// lives in the settings BAR: common at `common_offset`, then ISR +0x1000,
    /// device config +0x2000 and notify +0x3000 (crosvm and QEMU both do this).
    pub fn single_bar_layout(bar: u8, common_offset: u32, bar_len: u32) -> Result<Self, Error> {
        if bar_len < LAYOUT_BAR_MIN || common_offset > bar_len - LAYOUT_BAR_MIN {
            return Err(Error::BarTooSmall(bar));
        }
        let region = |off: u32, len: u32| Region {
            bar,
            offset: off,
            length: len,
            cap_offset: 0,
            id: 0,
            present: true,
        };
        Ok(Self {
            common: region(common_offset, LAYOUT_COMMON_SIZE),
            notify: region(common_offset + LAYOUT_NOTIFY_OFFSET, 0x1000),
            isr: Some(region(common_offset + LAYOUT_ISR_OFFSET, 1)),
            device: Some(region(common_offset + LAYOUT_DEVICE_OFFSET, 0x1000)),
            shm: None,
            notify_off_multiplier: NOTIFY_OFF_MULTIPLIER_DEFAULT,
        })
    }
}

pub struct StatusText(pub u8);

impl fmt::Display for StatusText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0;
        let mut first = true;
        for (bit, name) in [
            (STATUS_ACKNOWLEDGE, "ACK"),
            (STATUS_DRIVER, "DRIVER"),
            (STATUS_DRIVER_OK, "DRIVER_OK"),
            (STATUS_FEATURES_OK, "FEATURES_OK"),
            (STATUS_NEEDS_RESET, "NEEDS_RESET"),
            (STATUS_FAILED, "FAILED"),
        ] {
            if s & bit != 0 {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("0")?;
        }
        Ok(())
    }
}

/// MMIO access to the four virtio PCI structures, mediated by the platform.
/// The kernel driver implements it with volatile accesses into the mapped BARs.
pub trait Mmio {
    fn common_read_u8(&self, off: u32) -> u8;
    fn common_read_u16(&self, off: u32) -> u16;
    fn common_read_u32(&self, off: u32) -> u32;
    fn common_write_u8(&mut self, off: u32, v: u8);
    fn common_write_u16(&mut self, off: u32, v: u16);
    fn common_write_u32(&mut self, off: u32, v: u32);
    fn notify(&mut self, off: u32, value: u16);
    fn device_read_u8(&self, off: u32) -> u8;
    fn device_read_u32(&self, off: u32) -> u32;
}

pub fn status(m: &mut dyn Mmio) -> u8 {
    m.common_read_u8(COMMON_DEVICE_STATUS)
}

pub fn set_status(m: &mut dyn Mmio, v: u8) {
    m.common_write_u8(COMMON_DEVICE_STATUS, v);
    fence(Ordering::SeqCst);
}

/// Reset + ACKNOWLEDGE/DRIVER + features + FEATURES_OK.
pub fn negotiate(m: &mut dyn Mmio, log: &mut dyn Log) -> Result<u64, Error> {
    set_status(m, 0);
    let mut reset = 0u8;
    for _ in 0..1000 {
        reset = status(m);
        if reset == 0 {
            break;
        }
    }
    if reset != 0 {
        vlog!(log, "reset: status still 0x{:02X} ({})", reset, StatusText(reset));
        return Err(Error::ResetTimeout(reset));
    }
    vlog!(log, "reset ok: status=0x00");

    set_status(m, STATUS_ACKNOWLEDGE);
    vlog!(log, "status <- ACKNOWLEDGE (0x{:02X})", STATUS_ACKNOWLEDGE);
    set_status(m, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    vlog!(
        log,
        "status <- ACK|DRIVER (0x{:02X})",
        STATUS_ACKNOWLEDGE | STATUS_DRIVER
    );

    m.common_write_u32(COMMON_DEVICE_FEATURE_SELECT, 0);
    let lo = m.common_read_u32(COMMON_DEVICE_FEATURE);
    m.common_write_u32(COMMON_DEVICE_FEATURE_SELECT, 1);
    let hi = m.common_read_u32(COMMON_DEVICE_FEATURE);
    let dev = (lo as u64) | ((hi as u64) << 32);
    vlog!(log, "device features = 0x{:016X} (lo=0x{:08X} hi=0x{:08X})", dev, lo, hi);
    for (bit, name) in [
        (29u32, "VIRTIO_RING_F_EVENT_IDX(29)"),
        (32u32, "VIRTIO_F_VERSION_1(32)"),
        (33u32, "VIRTIO_F_ACCESS_PLATFORM(33)"),
        (35u32, "VIRTIO_F_SUSPEND(35)"),
    ] {
        vlog!(
            log,
            "  bit {} {} = {}",
            bit,
            name,
            if dev & (1u64 << bit) != 0 { "yes" } else { "no" }
        );
    }
    if dev & VIRTIO_F_VERSION_1 == 0 {
        return Err(Error::VersionOneMissing(dev));
    }
    if dev & VIRTIO_F_ACCESS_PLATFORM != 0 {
        vlog!(
            log,
            "  ACCESS_PLATFORM offered but not negotiated (no IOMMU in this driver yet)"
        );
    }
    let driver = VIRTIO_F_VERSION_1;
    m.common_write_u32(COMMON_DRIVER_FEATURE_SELECT, 0);
    m.common_write_u32(COMMON_DRIVER_FEATURE, driver as u32);
    m.common_write_u32(COMMON_DRIVER_FEATURE_SELECT, 1);
    m.common_write_u32(COMMON_DRIVER_FEATURE, (driver >> 32) as u32);
    fence(Ordering::SeqCst);
    vlog!(
        log,
        "driver features <- 0x{:016X} (lo=0x{:08X} hi=0x{:08X})",
        driver,
        driver as u32,
        (driver >> 32) as u32
    );

    let s = status(m) | STATUS_FEATURES_OK;
    set_status(m, s);
    let got = status(m);
    vlog!(
        log,
        "status <- 0x{:02X} ({}), read back 0x{:02X} ({})",
        s,
        StatusText(s),
        got,
        StatusText(got)
    );
    if got & STATUS_FEATURES_OK == 0 {
        return Err(Error::FeaturesOkRejected(got));
    }
    Ok(VIRTIO_F_VERSION_1)
}

pub fn queue_mem_size(size: u16) -> usize {
    let n = size as usize;
    let desc = 16 * n;
    let avail = 4 + 2 * n;
    let used = 4 + 8 * n;
    desc + avail + used + 8
}

#[derive(Clone, Copy)]
pub struct VringMem {
    pub va: *mut u8,
    pub pa: u64,
    pub len: usize,
}

#[derive(Clone, Copy)]
pub struct Queue {
    pub index: u16,
    pub size: u16,
    pub desc: *mut u8,
    pub avail: *mut u8,
    pub used: *mut u8,
    pub desc_pa: u64,
    pub avail_pa: u64,
    pub used_pa: u64,
    /// Byte offset passed to [`Mmio::notify`] (already multiplied).
    pub notify_off: u32,
    pub last_avail: u16,
    pub last_used: u16,
}

/// Program one split virtqueue from `mem` and wait for `queue_enable` to stick.
pub fn setup_queue(
    m: &mut dyn Mmio,
    index: u16,
    mem: VringMem,
    max_size: u16,
    notify_off_multiplier: u32,
    name: &str,
    log: &mut dyn Log,
) -> Result<Queue, Error> {
    m.common_write_u16(COMMON_QUEUE_SELECT, index);
    let max = m.common_read_u16(COMMON_QUEUE_SIZE);
    vlog!(log, "queue{} ({}) device max size={}", index, name, max);
    if max < 8 {
        return Err(Error::QueueTooSmall(max));
    }
    let mut size = max;
    while size > max_size {
        size /= 2;
    }
    if size < 8 || size & (size - 1) != 0 {
        return Err(Error::QueueTooSmall(size));
    }
    let need = queue_mem_size(size);
    if mem.len < need {
        return Err(Error::QueueMemorySmall(mem.len, need));
    }
    let n = size as usize;
    let avail_off = 16 * n;
    let used_off = (avail_off + 4 + 2 * n + 3) & !3usize;
    let desc = mem.va;
    let avail = unsafe { mem.va.add(avail_off) };
    let used = unsafe { mem.va.add(used_off) };
    let desc_pa = mem.pa;
    let avail_pa = mem.pa + avail_off as u64;
    let used_pa = mem.pa + used_off as u64;

    m.common_write_u16(COMMON_QUEUE_SIZE, size);
    m.common_write_u32(COMMON_QUEUE_DESC, desc_pa as u32);
    m.common_write_u32(COMMON_QUEUE_DESC + 4, (desc_pa >> 32) as u32);
    m.common_write_u32(COMMON_QUEUE_DRIVER, avail_pa as u32);
    m.common_write_u32(COMMON_QUEUE_DRIVER + 4, (avail_pa >> 32) as u32);
    m.common_write_u32(COMMON_QUEUE_DEVICE, used_pa as u32);
    m.common_write_u32(COMMON_QUEUE_DEVICE + 4, (used_pa >> 32) as u32);
    // Polling mode: disable the MSI-X vector for this queue.
    m.common_write_u16(COMMON_QUEUE_MSIX_VECTOR, VIRTIO_MSI_NO_VECTOR);
    m.common_write_u16(COMMON_QUEUE_ENABLE, 1);
    fence(Ordering::SeqCst);

    let enable = m.common_read_u16(COMMON_QUEUE_ENABLE);
    let got_size = m.common_read_u16(COMMON_QUEUE_SIZE);
    let notify_off = m.common_read_u16(COMMON_QUEUE_NOTIFY_OFF);
    let notify_byte_off = notify_off as u32 * notify_off_multiplier;
    vlog!(
        log,
        "queue{} desc=0x{:X} avail=0x{:X} used=0x{:X} size={}",
        index,
        desc_pa,
        avail_pa,
        used_pa,
        got_size
    );
    vlog!(
        log,
        "queue{} msix=0x{:04X} notify_off={} (byte 0x{:X}) enable={}",
        index,
        VIRTIO_MSI_NO_VECTOR,
        notify_off,
        notify_byte_off,
        enable
    );
    if enable != 1 || got_size != size {
        return Err(Error::QueueNotReady(enable, got_size));
    }
    vlog!(log, "queue{} READY (enable=1, size={})", index, got_size);

    Ok(Queue {
        index,
        size,
        desc,
        avail,
        used,
        desc_pa,
        avail_pa,
        used_pa,
        notify_off: notify_byte_off,
        last_avail: 0,
        last_used: 0,
    })
}

pub fn driver_ok(m: &mut dyn Mmio, log: &mut dyn Log) -> Result<(), Error> {
    let s = status(m) | STATUS_DRIVER_OK;
    set_status(m, s);
    let got = status(m);
    vlog!(
        log,
        "status <- 0x{:02X} ({}), read back 0x{:02X} ({})",
        s,
        StatusText(s),
        got,
        StatusText(got)
    );
    if got & STATUS_FAILED != 0 {
        return Err(Error::DeviceStatus(got));
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
pub struct MediaConfig {
    pub device_caps: u32,
    pub device_type: u32,
    pub card: [u8; 32],
}

pub fn read_media_config(m: &dyn Mmio, log: &mut dyn Log) -> Result<MediaConfig, Error> {
    let mut cfg = MediaConfig::default();
    cfg.device_caps = m.device_read_u32(0);
    cfg.device_type = m.device_read_u32(4);
    for (i, b) in cfg.card.iter_mut().enumerate() {
        *b = m.device_read_u8(8 + i as u32);
    }
    let end = cfg.card.iter().position(|&b| b == 0).unwrap_or(cfg.card.len());
    let mut card = LineBuf::new();
    for &b in &cfg.card[..end] {
        let _ = card.write_char(if b >= 0x20 && b < 0x7f { b as char } else { '?' });
    }
    vlog!(
        log,
        "device_cfg: device_caps=0x{:08X} device_type={} card=\"{}\"",
        cfg.device_caps,
        cfg.device_type,
        card.as_str()
    );
    Ok(cfg)
}

#[derive(Clone, Copy)]
pub struct Buf {
    pub va: *mut u8,
    pub pa: u64,
    pub len: usize,
}

pub fn write_buf(buf: &Buf, data: &[u8]) {
    let n = core::cmp::min(data.len(), buf.len);
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf.va, n) };
    fence(Ordering::SeqCst);
}

pub fn read_buf(buf: &Buf, out: &mut [u8]) -> usize {
    fence(Ordering::SeqCst);
    let n = core::cmp::min(out.len(), buf.len);
    unsafe { ptr::copy_nonoverlapping(buf.va, out.as_mut_ptr(), n) };
    n
}

/// Submit one descriptor chain (readable `req`, writable `resp`) and poll the
/// used ring until the device returns it. `stall` is called between polls.
pub fn submit(
    m: &mut dyn Mmio,
    q: &mut Queue,
    req: &Buf,
    resp: &Buf,
    stall: &mut dyn FnMut(),
    log: &mut dyn Log,
) -> Result<usize, Error> {
    if req.len == 0 || req.len > u32::MAX as usize || resp.len > u32::MAX as usize {
        return Err(Error::QueueMemorySmall(req.len.max(resp.len), u32::MAX as usize));
    }
    unsafe {
        let d0 = q.desc;
        let d1 = q.desc.add(16);
        ptr::write_volatile(d0 as *mut u32, req.pa as u32);
        ptr::write_volatile(d0.add(4) as *mut u32, (req.pa >> 32) as u32);
        ptr::write_volatile(d0.add(8) as *mut u32, req.len as u32);
        ptr::write_volatile(d0.add(12) as *mut u16, VIRTQ_DESC_F_NEXT);
        ptr::write_volatile(d0.add(14) as *mut u16, 1);
        ptr::write_volatile(d1 as *mut u32, resp.pa as u32);
        ptr::write_volatile(d1.add(4) as *mut u32, (resp.pa >> 32) as u32);
        ptr::write_volatile(d1.add(8) as *mut u32, resp.len as u32);
        ptr::write_volatile(d1.add(12) as *mut u16, VIRTQ_DESC_F_WRITE);
        ptr::write_volatile(d1.add(14) as *mut u16, 0);
        fence(Ordering::SeqCst);

        let slot = q.last_avail as usize % q.size as usize;
        ptr::write_volatile(q.avail.add(4 + 2 * slot) as *mut u16, 0u16);
        fence(Ordering::SeqCst);
        let next_avail = q.last_avail.wrapping_add(1);
        ptr::write_volatile(q.avail.add(2) as *mut u16, next_avail);
        fence(Ordering::SeqCst);
        q.last_avail = next_avail;

        m.notify(q.notify_off, q.index);
        fence(Ordering::SeqCst);

        let mut spins = 0u32;
        while ptr::read_volatile(q.used.add(2) as *const u16) == q.last_used {
            if spins >= 2000 {
                vlog!(
                    log,
                    "queue{} TIMEOUT waiting for used.idx (want {}, have {}, avail.idx={})",
                    q.index,
                    q.last_used.wrapping_add(1),
                    ptr::read_volatile(q.used.add(2) as *const u16),
                    q.last_avail
                );
                return Err(Error::ResponseTimeout(q.index, q.last_used, q.last_avail));
            }
            stall();
            spins += 1;
        }
        fence(Ordering::SeqCst);

        let slot = q.last_used as usize % q.size as usize;
        let id = ptr::read_volatile(q.used.add(4 + 8 * slot) as *const u32);
        let len = ptr::read_volatile(q.used.add(8 + 8 * slot) as *const u32);
        q.last_used = q.last_used.wrapping_add(1);
        vlog!(log, "queue{} used entry: id={} len={}", q.index, id, len);
        if id != 0 {
            return Err(Error::UsedId(id));
        }
        Ok(len as usize)
    }
}

pub fn hex_line(out: &mut LineBuf, data: &[u8], max: usize) -> usize {
    let n = core::cmp::min(data.len(), max);
    for (i, b) in data[..n].iter().enumerate() {
        if i != 0 {
            let _ = out.write_str(" ");
        }
        let _ = write!(out, "{:02X}", b);
    }
    n
}
