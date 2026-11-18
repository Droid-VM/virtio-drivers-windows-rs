//! One-shot present-surface capture for field debugging.
//!
//! Enabled by `HKLM\SYSTEM\CurrentControlSet\Services\VirtioGpu\Parameters\PresentDump`
//! (REG_DWORD, 1 = on, 0/absent = off).  The first four presents after boot are
//! written to `\SystemRoot\Temp\vgpu-present-<n>.bin`:
//!
//! ```text
//! offset 0   "VGPD"                        magic
//! offset 4   u32 width
//! offset 8   u32 height
//! offset 12  u32 stride (bytes per row)
//! offset 16  u32 format (virgl fourcc)
//! offset 20  u32 src allocation id
//! offset 24  i32 src_rect.left, top, right, bottom
//! offset 40  i32 dst_rect.left, top, right, bottom
//! offset 56  u32 flags (DXGKARG_flags.Value)
//! offset 60  u32 reserved
//! offset 64  raw pixels, top-down, `stride` bytes per row
//! ```
//!
//! This is a diagnostic, not a feature: each call blocks the present path while
//! the file is written, so it is capped and off by default.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use wdk::wdm::{HANDLE, KeGetCurrentIrql};

use crate::allocation::{Allocation, VirtioResource};

const MAX_DUMPS: u32 = 2;
const CHUNK: usize = 32 * 1024;

/// Re-read the registry every this many presents, so the switch can be armed
/// while the desktop is already running (waiting for a reboot would burn the
/// budget on the logon screen instead of the application under test).
const RECHECK_EVERY: u32 = 120;

static ARMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static TICK: AtomicU32 = AtomicU32::new(0);
static WRITTEN: AtomicU32 = AtomicU32::new(0);

fn refresh_armed() -> bool {
    if WRITTEN.load(Ordering::Relaxed) >= MAX_DUMPS {
        return false;
    }
    let armed = ARMED.load(Ordering::Relaxed);
    if TICK.fetch_add(1, Ordering::Relaxed) % RECHECK_EVERY == 0 {
        let on = crate::bringup::read_parameter("PresentDump").unwrap_or(0) == 1;
        ARMED.store(on, Ordering::Relaxed);
        return on;
    }
    armed
}

#[repr(C)]
struct IoStatusBlock {
    status: *mut core::ffi::c_void,
    information: usize,
}

unsafe extern "system" {
    fn ZwCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut wdk::wdm::OBJECT_ATTRIBUTES,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut core::ffi::c_void,
        ea_length: u32,
    ) -> i32;

    fn ZwWriteFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: *mut core::ffi::c_void,
        apc_context: *mut core::ffi::c_void,
        io_status_block: *mut IoStatusBlock,
        buffer: *mut core::ffi::c_void,
        length: u32,
        byte_offset: *mut i64,
        key: *mut u32,
    ) -> i32;
}

const GENERIC_WRITE: u32 = 0x4000_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;

/// `DXGKARG_flags` is a bitfield union; the raw value is what matters here.
pub fn maybe_dump(
    alloc: &Allocation,
    src_rect: (i32, i32, i32, i32),
    dst_rect: (i32, i32, i32, i32),
    flags: u32,
) {
    if unsafe { KeGetCurrentIrql() } != 0 || !refresh_armed() {
        return;
    }
    if WRITTEN.load(Ordering::Relaxed) >= MAX_DUMPS {
        return;
    }

    let (width, height, stride, format) = match alloc.resource() {
        VirtioResource::Blob { info, .. } => {
            let Some(info) = *info.read() else { return };
            (info.width, info.height, info.strides[0], info.format)
        },
        _ => return,
    };
    if width == 0 || height == 0 || stride < width.saturating_mul(4) {
        return;
    }
    // Optional floor: `PresentDumpMinWidth` lets the operator target the
    // full-screen desktop composite instead of a window-sized surface.
    let min_width = crate::bringup::read_parameter("PresentDumpMinWidth").unwrap_or(0);
    if width < min_width {
        return;
    }

    let Ok(pixels) = alloc.kernel_address() else { return };

    let index = WRITTEN.fetch_add(1, Ordering::Relaxed);
    if index >= MAX_DUMPS {
        return;
    }

    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(b"VGPD");
    header[4..8].copy_from_slice(&width.to_le_bytes());
    header[8..12].copy_from_slice(&height.to_le_bytes());
    header[12..16].copy_from_slice(&stride.to_le_bytes());
    header[16..20].copy_from_slice(&format.to_le_bytes());
    header[20..24].copy_from_slice(&alloc.id().map(|id| id.get()).unwrap_or(0).to_le_bytes());
    header[24..28].copy_from_slice(&src_rect.0.to_le_bytes());
    header[28..32].copy_from_slice(&src_rect.1.to_le_bytes());
    header[32..36].copy_from_slice(&src_rect.2.to_le_bytes());
    header[36..40].copy_from_slice(&src_rect.3.to_le_bytes());
    header[40..44].copy_from_slice(&dst_rect.0.to_le_bytes());
    header[44..48].copy_from_slice(&dst_rect.1.to_le_bytes());
    header[48..52].copy_from_slice(&dst_rect.2.to_le_bytes());
    header[52..56].copy_from_slice(&dst_rect.3.to_le_bytes());
    header[56..60].copy_from_slice(&flags.to_le_bytes());

    if let Err(status) = write_file(index, &header, pixels.as_ptr(), width, height, stride) {
        log::error!("present dump {} failed: {:?}", index, status);
    }
}

fn write_file(
    index: u32,
    header: &[u8; 64],
    pixels: *const u8,
    width: u32,
    height: u32,
    stride: u32,
) -> Result<(), i32> {
    let mut path: alloc::vec::Vec<u16> =
        alloc::format!("\\SystemRoot\\Temp\\vgpu-present-{}.bin", index).encode_utf16().collect();
    let byte_len = (path.len() * 2) as u16;
    let mut name = wdk::wdm::UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: path.as_mut_ptr(),
    };
    let mut attrs: wdk::wdm::OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
    attrs.Length = core::mem::size_of::<wdk::wdm::OBJECT_ATTRIBUTES>() as u32;
    attrs.ObjectName = &mut name;
    attrs.Attributes = wdk::wdm::OBJ_CASE_INSENSITIVE | wdk::wdm::OBJ_KERNEL_HANDLE;

    let mut handle: HANDLE = core::ptr::null_mut();
    let mut iosb = IoStatusBlock { status: core::ptr::null_mut(), information: 0 };
    let status = unsafe {
        ZwCreateFile(
            &mut handle,
            GENERIC_WRITE | SYNCHRONIZE,
            &mut attrs,
            &mut iosb,
            core::ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_OVERWRITE_IF,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            core::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }

    let mut ok = write_all(handle, header.as_ptr(), header.len());
    if ok.is_ok() {
        // Row by row through a *heap* buffer.  A kernel stack is only a few
        // pages on ARM64: a 64 KiB local array overflowed it and bugchecked the
        // guest on the first present.
        let mut chunk: alloc::vec::Vec<u8> = alloc::vec![0u8; CHUNK];
        let row_bytes = stride as usize;
        let rows_per_chunk = if row_bytes == 0 { 0 } else { CHUNK / row_bytes };
        let rows_per_chunk = rows_per_chunk.max(1);

        'outer: for start in (0..height as usize).step_by(rows_per_chunk) {
            let rows = rows_per_chunk.min(height as usize - start);
            let len = rows * row_bytes;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    pixels.add(start * row_bytes),
                    chunk.as_mut_ptr(),
                    len,
                );
            }
            if let Err(e) = write_all(handle, chunk.as_ptr(), len) {
                ok = Err(e);
                break 'outer;
            }
        }
        let _ = width;
    }

    unsafe { wdk::wdm::ZwClose(handle) };
    ok
}

fn write_all(handle: HANDLE, mut buf: *const u8, mut len: usize) -> Result<(), i32> {
    while len > 0 {
        let n = len.min(CHUNK) as u32;
        let mut iosb = IoStatusBlock { status: core::ptr::null_mut(), information: 0 };
        let status = unsafe {
            ZwWriteFile(
                handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut iosb,
                buf as *mut core::ffi::c_void,
                n,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if status < 0 {
            return Err(status);
        }
        buf = unsafe { buf.add(n as usize) };
        len -= n as usize;
    }
    Ok(())
}
