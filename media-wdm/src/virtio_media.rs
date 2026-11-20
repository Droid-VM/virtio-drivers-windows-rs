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
pub const MEDIA_CMD_MMAP: u32 = 4;
pub const MEDIA_CMD_MUNMAP: u32 = 5;
pub const V4L2_IOCTL_QUERYCAP: u32 = 0;
pub const V4L2_IOCTL_ENUM_FMT: u32 = 2;
pub const V4L2_IOCTL_G_FMT: u32 = 4;
pub const V4L2_IOCTL_S_FMT: u32 = 5;
pub const V4L2_IOCTL_REQBUFS: u32 = 8;
pub const V4L2_IOCTL_QUERYBUF: u32 = 9;
pub const V4L2_IOCTL_QBUF: u32 = 15;
pub const V4L2_IOCTL_S_CTRL: u32 = 28;
pub const V4L2_IOCTL_STREAMON: u32 = 18;
pub const V4L2_IOCTL_STREAMOFF: u32 = 19;
pub const V4L2_IOCTL_SUBSCRIBE_EVENT: u32 = 90;
pub const V4L2_IOCTL_DECODER_CMD: u32 = 96;
pub const V4L2_IOCTL_ENCODER_CMD: u32 = 77;
pub const V4L2_DEC_CMD_STOP: u32 = 1;
pub const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
pub const V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE: u32 = 10;
pub const V4L2_MEMORY_MMAP: u32 = 1;
pub const V4L2_FIELD_NONE: u32 = 1;
pub const V4L2_PIX_FMT_H264: u32 = 0x3436_3248; // 'H264'
/// P-BATCH VP9: the OUTPUT fourcc that makes the host virtio-media decoder pick
/// its VP9 backend (c2.qti.vp9.decoder on the tablet).  'VP90' in memory, which
/// is what crosvm's decoder_adapter.rs maps to `Format::VP9`.
pub const V4L2_PIX_FMT_VP9: u32 = 0x3039_5056; // 'VP90'
/// P-BATCH HEVC: the OUTPUT fourcc that makes the host virtio-media decoder pick
/// its HEVC backend (c2.qti.hevc.decoder on the tablet).  'HEVC' in memory, the
/// Linux UAPI name (V4L2_PIX_FMT_HEVC == v4l2_fourcc('H','E','V','C')); crosvm's
/// decoder_adapter.rs maps it to `Format::HEVC`, and the guest side of the
/// virtio-media protocol is a byte stream, so this is the only place the codec
/// choice exists.
pub const V4L2_PIX_FMT_HEVC: u32 = 0x4356_4548; // 'HEVC'
/// P-BATCH AV1: the OUTPUT fourcc that makes the host virtio-media decoder pick
/// its AV1 backend (c2.qti.av1.decoder on the tablet).  'AV01' in memory, the
/// Linux UAPI name (V4L2_PIX_FMT_AV1 == v4l2_fourcc('A','V','0','1')); crosvm's
/// decoder_adapter.rs maps it to `Format::AV1`, and the guest side of the
/// virtio-media protocol is a byte stream, so this is the only place the codec
/// choice exists.
pub const V4L2_PIX_FMT_AV1: u32 = 0x3130_5641; // 'AV01'

pub const V4L2_PIX_FMT_NV12: u32 = 0x3231_564E; // 'NV12'
/// HEVC-MAIN10 (1.0.0.21): the 10-bit 4:2:0 CAPTURE fourcc, Linux UAPI
/// V4L2_PIX_FMT_P010 (v4l2_fourcc('P','0','1','0')).  A 10-bit Main10 session
/// asks S_FMT CAPTURE for this first; the crosvm virtio-media decoder that backs
/// the tablet currently answers NV12 for CAPTURE ("CAPTURE is always NV12",
/// host-ref video_decoder.rs:1666/1714), so configure_and_send logs the refusal
/// and falls back to NV12 -- the picture is then 8-bit, which the UMD converts
/// into its P010 surface MSB-aligned.
pub const V4L2_PIX_FMT_P010: u32 = 0x3031_3050; // 'P010'
// Linux UAPI value: V4L2_EVENT_SOURCE_CHANGE is 5 (V4L2_EVENT_VSYNC is 1).
// crosvm virtio-media maps 1 to VSync and rejects it with EINVAL.
pub const V4L2_EVENT_SOURCE_CHANGE: u32 = 5;
pub const VIRTIO_MEDIA_EVENT_ERROR: u32 = 0;
pub const VIRTIO_MEDIA_EVENT_DQBUF: u32 = 1;
pub const VIRTIO_MEDIA_EVENT_EVENT: u32 = 2;
pub const VIRTIO_MEDIA_MMAP_FLAG_RW: u32 = 1;

// `struct v4l2_buffer` (LP64, linux/videodev2.h): 88 bytes.
pub const V4L2_BUFFER_SIZE: usize = 88;
pub const V4L2_BUFFER_INDEX: usize = 0;
pub const V4L2_BUFFER_TYPE: usize = 4;
pub const V4L2_BUFFER_BYTESUSED: usize = 8;
pub const V4L2_BUFFER_FLAGS: usize = 12;
/// Linux UAPI V4L2_BUF_FLAG_KEYFRAME; encoder CAPTURE DQBUF carries I-frame status.
pub const V4L2_BUF_FLAG_KEYFRAME: u32 = 0x0000_0008;
pub const V4L2_BUF_FLAG_TIMESTAMP_COPY: u32 = 0x0000_4000;
pub const V4L2_BUFFER_FIELD: usize = 16;
pub const V4L2_BUFFER_TIMESTAMP: usize = 24;
pub const V4L2_BUFFER_SEQUENCE: usize = 56;
pub const V4L2_BUFFER_MEMORY: usize = 60;
pub const V4L2_BUFFER_OFFSET: usize = 64;
pub const V4L2_BUFFER_LENGTH: usize = 72;

// `struct v4l2_plane`: 64 bytes.
pub const V4L2_PLANE_SIZE: usize = 64;
pub const V4L2_PLANE_BYTESUSED: usize = 0;
pub const V4L2_PLANE_LENGTH: usize = 4;
pub const V4L2_PLANE_OFFSET: usize = 8;
pub const V4L2_PLANE_DATA_OFFSET: usize = 16;

// `struct v4l2_format`: 208 bytes; the union starts at offset 8.
pub const V4L2_FORMAT_SIZE: usize = 208;
pub const V4L2_FORMAT_TYPE: usize = 0;
pub const V4L2_FORMAT_WIDTH: usize = 8;
pub const V4L2_FORMAT_HEIGHT: usize = 12;
pub const V4L2_FORMAT_PIXELFORMAT: usize = 16;
pub const V4L2_FORMAT_FIELD: usize = 20;
pub const V4L2_FORMAT_SIZEIMAGE: usize = 28;
pub const V4L2_FORMAT_BYTESPERLINE: usize = 32;
pub const V4L2_FORMAT_NUM_PLANES: usize = 188;

// `struct v4l2_requestbuffers`: 20 bytes.
pub const V4L2_REQBUFS_SIZE: usize = 20;
pub const V4L2_REQBUFS_COUNT: usize = 0;
pub const V4L2_REQBUFS_TYPE: usize = 4;
pub const V4L2_REQBUFS_MEMORY: usize = 8;

// `struct v4l2_event`: 136 bytes; the union starts at offset 8.
pub const V4L2_EVENT_SIZE: usize = 136;
pub const V4L2_EVENT_TYPE: usize = 0;
pub const V4L2_EVENT_SRC_CHANGES: usize = 8;

// The virtio-media DQBUF event: EventHeader(8) + v4l2_buffer(88) + 8 planes(512).
pub const EVENT_DQBUF_PLANES_OFFSET: usize = 8 + V4L2_BUFFER_SIZE;
pub const EVENT_DQBUF_SIZE: usize = EVENT_DQBUF_PLANES_OFFSET + 8 * V4L2_PLANE_SIZE;
pub const EVENT_CAP: usize = 1024;
pub const EVENT_COUNT: u16 = 8;

pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

pub fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

pub fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

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
    PoolMissing,
    PoolTooSmall(u64, u64),
    IoctlFailed(u32, i32),
    /// The device answered with a Linux errno instead of payload.
    Errno(i32),
    EventTimeout(u32),
    ShortFrame(usize, usize),
    EventIndex(u32),
    FrameWrite(u32),
    /// P2-1: the caller's access unit does not fit the device output buffer.
    BitstreamTooLarge(usize, u32),
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
            Error::PoolMissing => "the ACPI MEDIA_HOST pool has not been announced yet",
            Error::PoolTooSmall(_, _) => "the media_host pool is smaller than the mapped buffer",
            Error::IoctlFailed(_, _) => "a V4L2 ioctl returned an errno",
            Error::Errno(_) => "the device returned a Linux errno",
            Error::EventTimeout(_) => "no DQBUF event arrived before the timeout",
            Error::ShortFrame(_, _) => "the decoded frame is shorter than the NV12 image",
            Error::EventIndex(_) => "an event referenced a buffer outside EVENT_COUNT",
            Error::FrameWrite(_) => "could not write frame.raw",
            Error::BitstreamTooLarge(_, _) => "the access unit is larger than the device output buffer",
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
    fn progress_events(&mut self) -> Result<(), Error> { Ok(()) }
    fn transport_poison(&mut self) {}
    fn transport_failed(&self) -> bool { false }

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
    /// `queue_msix_vector` as the device read it back: the MSI-X table entry
    /// index this queue raises, or [`VIRTIO_MSI_NO_VECTOR`] when the queue is
    /// polled (P-BATCH MSI-X, 1.0.0.17).
    pub msix: u16,
    pub last_avail: u16,
    pub last_used: u16,
    // ---- fire-and-forget command slots (1.0.0.12) ------------------------
    //
    // A synchronous command occupies descriptors 0/1 and the one request /
    // response pair the caller passes in, and blocks until the device answers.
    // The per-access-unit QBUF is different: the host decodes synchronously
    // inside the QBUF handler, so waiting for that answer is what made one AU
    // cost 63-68 ms (send 30 + get 33) at 1080p.  `submit_async` puts the same
    // descriptor pair on the ring in one of these slots and returns
    // immediately; `reap_async` collects the answers later.
    /// Request buffer of each async slot (distinct DMA, never shared with a sync command).
    pub async_req: [Buf; ASYNC_SLOTS],
    /// Response buffer of each async slot.
    pub async_resp: [Buf; ASYNC_SLOTS],
    /// Round-robin index of the slot the next [`submit_async`] will use.
    pub async_next: u8,
    /// Slot of the oldest command still outstanding: answers come back in the
    /// order the descriptors were queued, so this is the FIFO head.
    pub async_head: u8,
    /// Commands queued but not answered yet (0..=ASYNC_SLOTS).
    pub async_inflight: u8,
    /// First errno an async command answered with (0 = none). Kept so the
    /// caller that eventually reaps it can say what failed.
    ///
    /// PER-SESSION-LIVESTATE (1.0.0.25): the queue is one hardware resource, so
    /// the latch stays here -- but it now carries the **owner** of the command
    /// that set it (`async_err_owner`, a session slot index, or
    /// [`ASYNC_OWNER_ANY`] for a bookkeeping error that belongs to no session).
    /// Every command also records its owner in `async_owner[slot]`, so a reaped
    /// answer is attributed to the session that submitted it and to nobody else.
    /// Before 1.0.0.25 the latch was device-wide: session B's SEND reported the
    /// errno of session A's dropped access unit, and A never learned about it.
    pub async_err: i32,
    /// Session slot that owns [`Queue::async_err`] (see above).
    pub async_err_owner: u8,
    /// Owner (session slot) of the command in each async slot.
    pub async_owner: [u8; ASYNC_SLOTS],
}

/// Owner tag meaning "no session": a queue-accounting error, reported to
/// whichever session reaps it.
pub const ASYNC_OWNER_ANY: u8 = 0xFF;

/// Number of fire-and-forget command slots on the command queue.
pub const ASYNC_SLOTS: usize = 4;

/// Descriptor index of async slot `slot`'s request descriptor. 0/1 belong to the
/// synchronous chain in [`submit`].
pub const fn async_desc_head(slot: usize) -> u16 {
    2 + 2 * slot as u16
}

/// Give queue `q` the DMA buffers of its async slots. Called once at bring-up.
pub fn set_async_slots(q: &mut Queue, req: [Buf; ASYNC_SLOTS], resp: [Buf; ASYNC_SLOTS]) {
    q.async_req = req;
    q.async_resp = resp;
    q.async_next = 0;
    q.async_head = 0;
    q.async_inflight = 0;
    q.async_err = 0;
    q.async_err_owner = ASYNC_OWNER_ANY;
    q.async_owner = [ASYNC_OWNER_ANY; ASYNC_SLOTS];
}

/// Program one split virtqueue from `mem` and wait for `queue_enable` to stick.
///
/// `msix_vector` is written to `queue_msix_vector` **before** `queue_enable`
/// (crosvm silently ignores vector writes once the queue is ready -- `queue.rs:159`
/// -- so it has to go in as part of queue setup): the MSI-X table entry index from
/// `irq::install`, or [`VIRTIO_MSI_NO_VECTOR`] to keep the queue on the polling
/// path.
pub fn setup_queue(
    m: &mut dyn Mmio,
    index: u16,
    mem: VringMem,
    max_size: u16,
    notify_off_multiplier: u32,
    msix_vector: u16,
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
    // P-BATCH MSI-X (1.0.0.17): tell the device which MSI-X table entry this
    // queue raises, or NO_VECTOR to keep it on the polling path. Written before
    // queue_enable on purpose (see the doc comment).
    m.common_write_u16(COMMON_QUEUE_MSIX_VECTOR, msix_vector);
    m.common_write_u16(COMMON_QUEUE_ENABLE, 1);
    fence(Ordering::SeqCst);

    let enable = m.common_read_u16(COMMON_QUEUE_ENABLE);
    let got_size = m.common_read_u16(COMMON_QUEUE_SIZE);
    let got_msix = m.common_read_u16(COMMON_QUEUE_MSIX_VECTOR);
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
        "queue{} msix_vector write 0x{:04X} readback 0x{:04X} ({}) notify_off={} (byte 0x{:X}) enable={}",
        index,
        msix_vector,
        got_msix,
        if got_msix == VIRTIO_MSI_NO_VECTOR { "polled" } else { "interrupt" },
        notify_off,
        notify_byte_off,
        enable
    );
    if got_msix != msix_vector {
        // virtio 1.x: the device answers NO_VECTOR when it cannot use that
        // vector. Keep the queue working (the used ring is still polled) but say
        // so, because it means the interrupt path is off for this queue.
        vlog!(
            log,
            "queue{} did not accept msix_vector 0x{:04X} (device says 0x{:04X}); queue stays polled",
            index,
            msix_vector,
            got_msix
        );
    }
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
        msix: got_msix,
        last_avail: 0,
        last_used: 0,
        async_req: [Buf::empty(); ASYNC_SLOTS],
        async_resp: [Buf::empty(); ASYNC_SLOTS],
        async_next: 0,
        async_head: 0,
        async_inflight: 0,
        async_err: 0,
        async_err_owner: ASYNC_OWNER_ANY,
        async_owner: [ASYNC_OWNER_ANY; ASYNC_SLOTS],
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

/// `num_queues` from `common_cfg` (virtio 1.x 4.1.4.3, offset 0x12). The
/// virtio-pci MSI-X table has one entry per queue plus one config entry, so this
/// is the bound the `queue_msix_vector` sanity check in `irq::install` uses
/// (P-BATCH MSI-X).
pub fn num_queues(m: &dyn Mmio) -> u16 {
    m.common_read_u16(COMMON_NUM_QUEUES)
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

impl Buf {
    pub const fn empty() -> Self {
        Self { va: ptr::null_mut(), pa: 0, len: 0 }
    }
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

/// Write the two descriptors of one command chain at descriptor index `head` and
/// put that index on the available ring. Does not wait for an answer.
unsafe fn post_chain(q: &mut Queue, head: u16, req: &Buf, resp: &Buf, m: &mut dyn Mmio) {
    unsafe {
        let d0 = q.desc.add(16 * head as usize);
        let d1 = q.desc.add(16 * (head as usize + 1));
        ptr::write_volatile(d0 as *mut u32, req.pa as u32);
        ptr::write_volatile(d0.add(4) as *mut u32, (req.pa >> 32) as u32);
        ptr::write_volatile(d0.add(8) as *mut u32, req.len as u32);
        ptr::write_volatile(d0.add(12) as *mut u16, VIRTQ_DESC_F_NEXT);
        ptr::write_volatile(d0.add(14) as *mut u16, head + 1);
        ptr::write_volatile(d1 as *mut u32, resp.pa as u32);
        ptr::write_volatile(d1.add(4) as *mut u32, (resp.pa >> 32) as u32);
        ptr::write_volatile(d1.add(8) as *mut u32, resp.len as u32);
        ptr::write_volatile(d1.add(12) as *mut u16, VIRTQ_DESC_F_WRITE);
        ptr::write_volatile(d1.add(14) as *mut u16, 0);
        fence(Ordering::SeqCst);

        let slot = q.last_avail as usize % q.size as usize;
        ptr::write_volatile(q.avail.add(4 + 2 * slot) as *mut u16, head);
        fence(Ordering::SeqCst);
        let next_avail = q.last_avail.wrapping_add(1);
        ptr::write_volatile(q.avail.add(2) as *mut u16, next_avail);
        fence(Ordering::SeqCst);
        q.last_avail = next_avail;

        m.notify(q.notify_off, q.index);
        fence(Ordering::SeqCst);
    }
}

/// Queue one command **without waiting** for the device to answer it.
///
/// Returns the slot the command went into. The answer is collected by
/// [`reap_async`]; every synchronous [`submit`] reaps first, so a sync command
/// can never read an async command's used entry.
pub fn submit_async(
    m: &mut dyn Mmio,
    q: &mut Queue,
    req: &[u8],
    stall: &mut dyn FnMut(),
    max_spins: u32,
    owner: u8,
    log: &mut dyn Log,
) -> Result<u8, Error> {
    if req.is_empty() || req.len() > u32::MAX as usize {
        return Err(Error::QueueMemorySmall(req.len(), u32::MAX as usize));
    }
    // Make room if every slot is still in flight (only reachable when the
    // client sends faster than the host decodes).
    if q.async_inflight as usize >= ASYNC_SLOTS {
        vlog!(
            log,
            "queue{} async: all {} slots in flight, waiting for one to come back",
            q.index,
            ASYNC_SLOTS
        );
        reap_async(m, q, stall, max_spins, true, log)?;
    }
    // Opportunistically collect the ones already answered.
    reap_async(m, q, stall, 0, false, log)?;
    if q.async_inflight as usize >= ASYNC_SLOTS {
        return Err(Error::ResponseTimeout(q.index, q.last_used, q.last_avail));
    }
    if m.transport_failed() { return Err(Error::DeviceStatus(0xFF)); }
    let slot = q.async_next as usize % ASYNC_SLOTS;
    let rb = q.async_req[slot];
    let sb = q.async_resp[slot];
    if rb.va.is_null() || req.len() > rb.len {
        return Err(Error::QueueMemorySmall(req.len(), rb.len));
    }
    write_buf(&rb, req);
    let head = async_desc_head(slot);
    let req_buf = Buf { len: req.len(), ..rb };
    // PER-SESSION-LIVESTATE (1.0.0.25): remember whose command this is *before*
    // it can be answered, so `reap_async` can credit the errno to that session.
    q.async_owner[slot] = owner;
    unsafe { post_chain(q, head, &req_buf, &sb, m) };
    q.async_next = ((slot + 1) % ASYNC_SLOTS) as u8;
    q.async_inflight += 1;
    Ok(slot as u8)
}

/// Collect answers to [`submit_async`] commands, oldest first.
///
/// `wait_all` blocks until every outstanding command has been answered;
/// otherwise it only takes the ones the device already returned. An error answer
/// is remembered in `q.async_err` and logged, so the client's next IOCTL can
/// report it without the driver having to guess where it came from.
pub fn reap_async(
    m: &mut dyn Mmio,
    q: &mut Queue,
    stall: &mut dyn FnMut(),
    max_spins: u32,
    wait_all: bool,
    log: &mut dyn Log,
) -> Result<(), Error> {
    if m.transport_failed() { return Err(Error::DeviceStatus(0xFF)); }
    let mut spins = 0u32;
    while q.async_inflight > 0 {
        // Harvest even if no interrupt object exists (polling fallback).
        let _ = m.progress_events();
        unsafe {
            fence(Ordering::SeqCst);
            let have = ptr::read_volatile(q.used.add(2) as *const u16);
            if have == q.last_used {
                if !wait_all {
                    break;
                }
                if spins >= max_spins {
                    vlog!(
                        log,
                        "queue{} async TIMEOUT: {} command(s) still in flight (used.idx={} last_used={} avail.idx={})",
                        q.index,
                        q.async_inflight,
                        have,
                        q.last_used,
                        q.last_avail
                    );
                    m.transport_poison();
                    return Err(Error::ResponseTimeout(q.index, q.last_used, q.last_avail));
                }
                spins += 1;
                stall();
                continue;
            }
            let used_slot = q.last_used as usize % q.size as usize;
            let id = ptr::read_volatile(q.used.add(4 + 8 * used_slot) as *const u32);
            q.last_used = q.last_used.wrapping_add(1);
            let want = async_desc_head(q.async_head as usize) as u32;
            let idx = (want as usize - 2) / 2;
            q.async_head = ((q.async_head as usize + 1) % ASYNC_SLOTS) as u8;
            q.async_inflight -= 1;
            if id != want {
                m.transport_poison();
                vlog!(
                    log,
                    "queue{} async: used entry id={} but descriptor {} was expected (accounting broken)",
                    q.index,
                    id,
                    want
                );
                if q.async_err == 0 {
                    q.async_err = -22;
                    q.async_err_owner = ASYNC_OWNER_ANY;
                }
                continue;
            }
            let resp = q.async_resp[idx];
            let mut hdr = [0u8; 8];
            if read_buf(&resp, &mut hdr) >= 4 {
                let errno = i32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
                if errno != 0 {
                    vlog!(log, "queue{} async command answered errno={} ({})", q.index, errno, -errno);
                    if q.async_err == 0 {
                        q.async_err = errno;
                        // 1.0.0.25: credit it to the session that submitted it.
                        q.async_err_owner = q.async_owner[idx];
                    }
                }
            }
        }
    }
    m.progress_events()?;
    Ok(())
}

/// PER-SESSION-LIVESTATE (1.0.0.25): take the latched async errno **only when it
/// belongs to `owner`** (a session slot index).  A session therefore never
/// reports another session's dropped access unit; `ASYNC_OWNER_ANY` (queue
/// accounting) is reported to whichever session reaps it first.
pub fn take_async_err(q: &mut Queue, owner: u8) -> i32 {
    if q.async_err != 0 && (q.async_err_owner == owner || q.async_err_owner == ASYNC_OWNER_ANY) {
        let errno = q.async_err;
        q.async_err = 0;
        q.async_err_owner = ASYNC_OWNER_ANY;
        errno
    } else {
        0
    }
}

/// Forget a latched errno that belongs to `owner`: that session is gone, so the
/// next session to reuse the slot must not inherit it.
pub fn clear_async_err(q: &mut Queue, owner: u8) {
    if q.async_err_owner == owner {
        q.async_err = 0;
        q.async_err_owner = ASYNC_OWNER_ANY;
    }
}

/// Submit one descriptor chain (readable `req`, writable `resp`) and wait for the
/// device to return it on the used ring. `stall` is called between looks; since
/// P-BATCH MSI-X (1.0.0.17) that is `irq::wait()` -- a 500 us interrupt wait
/// that falls back to the old `KeStallExecutionProcessor(500)` busy stall.
pub fn submit(
    m: &mut dyn Mmio,
    q: &mut Queue,
    req: &Buf,
    resp: &Buf,
    stall: &mut dyn FnMut(),
    max_spins: u32,
    log: &mut dyn Log,
) -> Result<usize, Error> {
    m.progress_events()?;
    if m.transport_failed() { return Err(Error::DeviceStatus(0xFF)); }
    if req.len == 0 || req.len > u32::MAX as usize || resp.len > u32::MAX as usize {
        return Err(Error::QueueMemorySmall(req.len.max(resp.len), u32::MAX as usize));
    }
    // A synchronous command must not be confused with an outstanding async one:
    // both use the same used ring, so drain the async completions first.
    reap_async(m, q, stall, max_spins, true, log)?;
    unsafe {
        m.progress_events()?;
        post_chain(q, 0, req, resp, m);

        let mut spins = 0u32;
        while ptr::read_volatile(q.used.add(2) as *const u16) == q.last_used {
            let _ = m.progress_events();
            if spins >= max_spins {
                vlog!(
                    log,
                    "queue{} TIMEOUT waiting for used.idx (want {}, have {}, avail.idx={})",
                    q.index,
                    q.last_used.wrapping_add(1),
                    ptr::read_volatile(q.used.add(2) as *const u16),
                    q.last_avail
                );
                m.transport_poison();
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
            m.transport_poison();
            return Err(Error::UsedId(id));
        }
        m.progress_events()?;
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

/// Post one device-writable buffer on the event queue. `id` is the descriptor
/// index (and the value the device returns in `used.ring[].id`).
pub fn post_event(m: &mut dyn Mmio, q: &mut Queue, buf: &Buf, id: u16) {
    if id >= q.size {
        return;
    }
    unsafe {
        let d = q.desc.add(16 * id as usize);
        ptr::write_volatile(d as *mut u32, buf.pa as u32);
        ptr::write_volatile(d.add(4) as *mut u32, (buf.pa >> 32) as u32);
        ptr::write_volatile(d.add(8) as *mut u32, buf.len as u32);
        ptr::write_volatile(d.add(12) as *mut u16, VIRTQ_DESC_F_WRITE);
        ptr::write_volatile(d.add(14) as *mut u16, 0);
        fence(Ordering::SeqCst);

        let slot = q.last_avail as usize % q.size as usize;
        ptr::write_volatile(q.avail.add(4 + 2 * slot) as *mut u16, id);
        fence(Ordering::SeqCst);
        let next = q.last_avail.wrapping_add(1);
        ptr::write_volatile(q.avail.add(2) as *mut u16, next);
        fence(Ordering::SeqCst);
        q.last_avail = next;
        m.notify(q.notify_off, q.index);
        fence(Ordering::SeqCst);
    }
}

/// Non-blocking look at the event queue's used ring.
pub fn poll_event(q: &mut Queue) -> Option<(u32, u32)> {
    unsafe {
        fence(Ordering::SeqCst);
        if ptr::read_volatile(q.used.add(2) as *const u16) == q.last_used {
            return None;
        }
        let slot = q.last_used as usize % q.size as usize;
        let id = ptr::read_volatile(q.used.add(4 + 8 * slot) as *const u32);
        let len = ptr::read_volatile(q.used.add(8 + 8 * slot) as *const u32);
        fence(Ordering::SeqCst);
        q.last_used = q.last_used.wrapping_add(1);
        Some((id, len))
    }
}
