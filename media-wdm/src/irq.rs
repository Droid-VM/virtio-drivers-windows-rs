//! MSI-X interrupt path for the virtio-media PCI function (P-BATCH MSI-X, 1.0.0.17).
//!
//! Up to 1.0.0.16 the transport deliberately left every virtqueue at
//! `VIRTIO_MSI_NO_VECTOR` and **polled** the used ring: every wait spun on
//! `KeStallExecutionProcessor(500)` until the device wrote a used entry. That is
//! correct and it is what all the earlier batches measured, but it burns a core
//! for the whole length of a decode (a 30 fps stream means the IOCTL thread is
//! busy ~100 % of the time it is waiting for the host MediaCodec).
//!
//! This module is the interrupt path the virtio spec asks for:
//!
//! * [`create`] runs in `EvtDriverDeviceAdd` -- the canonical KMDF place -- and
//!   creates the one interrupt object this function needs.  With
//!   `MessageNumberLimit = 1` in the INF the OS allocates exactly one message, so
//!   the object is bound to it (or to the INTx line when MSI-X is refused) and the
//!   framework reconnects it on every start, which keeps `disable/enable` and
//!   `pnputil /restart-device` cycles working without create/delete churn.
//! * [`install`] runs in `EvtDevicePrepareHardware`, where the raw resource list
//!   says which MSI-X table entry the OS assigned; it range-checks that index and
//!   hands it back so the queues can program `queue_msix_vector`.
//! * `EvtInterruptIsr` reads the virtio ISR status byte. Under legacy INTx that
//!   read is what deasserts the line; under MSI-X it is not needed, but it is the
//!   only way to see *which* queue signalled (both queues share one vector), so
//!   the same ISR serves both cases. It then queues the work item.
//! * `EvtInterruptWorkItem` runs at PASSIVE_LEVEL -- so `KeSetEvent` is legal,
//!   which it is not at DIRQL -- and signals the device's auto-reset
//!   "ring progressed" event. It deliberately does **not** touch the used ring:
//!   the ring stays single-owner (the IOCTL thread), so there is no lock here.
//! * [`wait`] is what the 500 us busy stall became: one `KeWaitForSingleObject`
//!   with a 500 us timeout on that event. A delivered interrupt wakes the IOCTL
//!   thread in microseconds; the caller then re-reads the used ring exactly as
//!   before.
//!
//! Polling is kept, on purpose, through three independent mechanisms:
//!
//! 1. [`install`] leaves the vector at [`NO_VECTOR`] -- and therefore the queues
//!    on the 1.0.0.16 polling path -- when the OS did not grant a message
//!    interrupt (MSI-X disabled, no MSI-X capability, or an index that fails the
//!    range check below).
//! 2. [`wait`] bounds *every* wait with a timeout and the caller re-reads the
//!    used ring afterwards, so a completion that arrives without an interrupt is
//!    still seen (no wakeup is ever required for correctness).
//! 3. after [`FALLBACK_TIMEOUTS`] consecutive timeouts the cell switches back to
//!    the old busy stall (`poll_only`), and the next delivered interrupt clears
//!    that flag again, so a device that starts delivering MSI-X messages is
//!    picked up automatically.
//!
//! Nothing in here logs from an interrupt callback (no `DbgPrint`/registry write
//! at DIRQL): the ISR and the work item only bump counters, and the counters are
//! printed from [`log_summary`] on PASSIVE_LEVEL.

use core::fmt::Write as _;
use core::sync::atomic::AtomicU32;

use super::*;

/// `VIRTIO_MSI_NO_VECTOR` (virtio 1.x, `common_cfg` 0x1a `queue_msix_vector`): writing this to
/// `queue_msix_vector` keeps that queue on the polling path.
pub(crate) const NO_VECTOR: u16 = 0xFFFF;

/// One ring-progress wait: 500 us (5,000 x 100 ns). This is the budget a single
/// `KeStallExecutionProcessor(500)` iteration had before 1.0.0.17, so a
/// `COMMAND_SPINS` timeout still means the same wall-clock time.
const WAIT_TIMEOUT_100NS: i64 = -5_000;

/// Consecutive timed-out waits after which a cell stops waiting for the
/// interrupt and returns to the old busy stall. `KeWaitForSingleObject` rounds a
/// relative timeout up to the system tick (15.6 ms at the default 64 Hz), so
/// this costs at most ~125 ms before the driver is back to 1.0.0.16 behaviour.
/// Any interrupt clears the counter, so this is not a one-way door.
const FALLBACK_TIMEOUTS: u32 = 8;

/// `NTSTATUS` of `KeWaitForSingleObject` when the relative timeout expired.
const STATUS_TIMEOUT: u32 = 0x0000_0102;

/// `NTSTATUS` marker for "the interrupt object was never created".
const CREATE_FAILED: u32 = 0xFFFF_FFFF;

/// WDF function-table dispatch, same trick as the crate root's `wdf_table_fn!`
/// (the C headers use `FORCEINLINE` wrappers that bindgen does not emit).
macro_rules! wdf_fn {
    ($pfn:ty, $index:ident) => {{
        unsafe {
            transmute::<wdf::WDFFUNC, $pfn>(*wdf::WdfFunctions_01027.add(wdf::WDFFUNCENUM::$index.0 as usize))
        }
    }};
}

/// What the virtqueues must program, and whether an interrupt object exists.
#[derive(Clone, Copy)]
pub(crate) struct Msix {
    /// `queue_msix_vector` value: MSI-X table entry index, or [`NO_VECTOR`].
    pub(crate) vector: u16,
    /// A KMDF interrupt object exists (false = pure polling).
    pub(crate) installed: bool,
}

/// Per-device interrupt state. Keyed by `wdf::WDFDEVICE` (not by the mapping
/// slot: the slot is released on every stop, the device is not), and never
/// freed, so an interrupt callback that races with `EvtDeviceReleaseHardware`
/// always has valid memory to touch. The ring-progress event is allocated on
/// first use and intentionally leaked for the same reason.
struct IrqCell {
    device: wdf::WDFDEVICE,
    interrupt: wdf::WDFINTERRUPT,
    /// `WdfInterruptCreate` status from `EvtDriverDeviceAdd` (0 = created).
    /// Logged by [`install`], the first place that has a log sink.
    create_status: u32,
    /// Auto-reset event: waiters consume the signal, so a wakeup that arrives
    /// between "check the used ring" and "wait" is never lost.
    event: *mut wdm::KEVENT,
    /// The virtio ISR status byte in the mapped settings BAR (null when the
    /// device exposes no ISR cap).
    isr_va: *mut u8,
    /// 1 when the interrupt resource was a *message* interrupt
    /// (`CM_RESOURCE_INTERRUPT_MESSAGE`). Decides whether the ISR may use the
    /// virtio ISR status byte as "is this mine": under MSI-X the host does not
    /// have to touch that byte (crosvm explicitly does not, see its
    /// `Interrupt::signal`: "Don't need to set ISR for MSI-X interrupts"), while
    /// for legacy INTx reading it is mandatory to deassert the line.
    message: AtomicU32,
    /// MSI-X table entry index programmed into both queues (or [`NO_VECTOR`]).
    msix: u16,
    /// Deepest "consecutive waits without an interrupt" seen, for the summary.
    worst_dry: u32,
    /// 1 while the interrupt path is armed for this start.
    armed: AtomicU32,
    /// 1 after the fallback fired: [`wait`] busy-stalls and never blocks again
    /// until the next delivered interrupt clears it.
    poll_only: AtomicU32,
    /// Hardware interrupts (ISR entries that claimed the message).
    irqs: AtomicU64,
    /// Work items that ran (work items coalesce, so this can be < `irqs`).
    work_items: AtomicU64,
    /// Waiters that blocked on the event.
    waits: AtomicU64,
    /// Of those, the ones woken by the interrupt (not by the timeout).
    wakeups: AtomicU64,
    /// Of those, the ones that hit the 500 us timeout.
    timeouts: AtomicU64,
    /// How often the polling fallback took over (each episode is logged once).
    fallbacks: AtomicU64,
    /// Busy-stall iterations: 1.0.0.16 behaviour, still the release path.
    busy_stalls: AtomicU64,
    /// Consecutive timeouts, reset by every delivered interrupt.
    consecutive: AtomicU32,
}

const EMPTY_CELL: IrqCell = IrqCell {
    device: ptr::null_mut(),
    interrupt: ptr::null_mut(),
    create_status: CREATE_FAILED,
    event: ptr::null_mut(),
    isr_va: ptr::null_mut(),
    message: AtomicU32::new(0),
    msix: NO_VECTOR,
    worst_dry: 0,
    armed: AtomicU32::new(0),
    poll_only: AtomicU32::new(0),
    irqs: AtomicU64::new(0),
    work_items: AtomicU64::new(0),
    waits: AtomicU64::new(0),
    wakeups: AtomicU64::new(0),
    timeouts: AtomicU64::new(0),
    fallbacks: AtomicU64::new(0),
    busy_stalls: AtomicU64::new(0),
    consecutive: AtomicU32::new(0),
};

/// One cell per device (decoder and encoder are two separate functions).
/// No lock: only its own device's prepare/release/add callbacks write a cell,
/// and WDF serializes those per device.
static mut IRQ_CELLS: [IrqCell; MAX_SLOTS] = [EMPTY_CELL; MAX_SLOTS];

unsafe fn cell_base() -> *mut IrqCell {
    ptr::addr_of_mut!(IRQ_CELLS) as *mut IrqCell
}

/// The cell owned by `device`.
unsafe fn cell_for(device: wdf::WDFDEVICE) -> Option<*mut IrqCell> {
    if device.is_null() {
        return None;
    }
    let base = unsafe { cell_base() };
    for i in 0..MAX_SLOTS {
        let cell = unsafe { base.add(i) };
        let owner = unsafe { ptr::read_volatile(ptr::addr_of!((*cell).device)) };
        if owner == device {
            return Some(cell);
        }
    }
    None
}

/// The cell owned by `device`, claiming a free one if this device has none yet.
unsafe fn cell_claim(device: wdf::WDFDEVICE) -> Option<*mut IrqCell> {
    if let Some(cell) = unsafe { cell_for(device) } {
        return Some(cell);
    }
    let base = unsafe { cell_base() };
    for i in 0..MAX_SLOTS {
        let cell = unsafe { base.add(i) };
        let stale = unsafe { ptr::read_volatile(ptr::addr_of!((*cell).device)) };
        if stale.is_null() {
            unsafe { (*cell).device = device };
            return Some(cell);
        }
    }
    None
}

/// Find the cell an interrupt handle belongs to. Called from the ISR at DIRQL
/// and from the work item at PASSIVE; both only read handles, which are never
/// cleared once created (the object lives as long as the device does).
unsafe fn find_cell(interrupt: wdf::WDFINTERRUPT) -> Option<*mut IrqCell> {
    if interrupt.is_null() {
        return None;
    }
    let base = unsafe { cell_base() };
    for i in 0..MAX_SLOTS {
        let cell = unsafe { base.add(i) };
        let handle = unsafe { ptr::read_volatile(ptr::addr_of!((*cell).interrupt)) };
        if !handle.is_null() && handle == interrupt {
            return Some(cell);
        }
    }
    None
}

/// Allocate (once per device) the ring-progress event and zero the per-session
/// counters. Leaves the interrupt handle alone: it is created once in
/// `EvtDriverDeviceAdd` and outlives every start/stop cycle. PASSIVE_LEVEL.
unsafe fn reset_stats(cell: *mut IrqCell) {
    unsafe {
        if (*cell).event.is_null() {
            // Deliberately never freed: a work item that is still queued when the
            // device is released must not touch freed memory. ~32 bytes per cell.
            let event = Box::into_raw(Box::new(zeroed::<wdm::KEVENT>()));
            wdm::KeInitializeEvent(event, wdm::EVENT_TYPE::SynchronizationEvent, 0);
            (*cell).event = event;
        } else {
            wdm::KeClearEvent((*cell).event);
        }
        (*cell).isr_va = ptr::null_mut();
        (*cell).message.store(0, Ordering::SeqCst);
        (*cell).msix = NO_VECTOR;
        (*cell).worst_dry = 0;
        (*cell).armed.store(0, Ordering::SeqCst);
        (*cell).poll_only.store(0, Ordering::SeqCst);
        (*cell).irqs.store(0, Ordering::SeqCst);
        (*cell).work_items.store(0, Ordering::SeqCst);
        (*cell).waits.store(0, Ordering::SeqCst);
        (*cell).wakeups.store(0, Ordering::SeqCst);
        (*cell).timeouts.store(0, Ordering::SeqCst);
        (*cell).fallbacks.store(0, Ordering::SeqCst);
        (*cell).busy_stalls.store(0, Ordering::SeqCst);
        (*cell).consecutive.store(0, Ordering::SeqCst);
    }
}

/// The first interrupt descriptor of `list`, plus what the raw list says about
/// the message: `(descriptor, is_message, table_index, message_count)`.
unsafe fn first_interrupt(
    list: wdf::WDFCMRESLIST,
) -> Option<(wdf::PCM_PARTIAL_RESOURCE_DESCRIPTOR, bool, u32, u16)> {
    let get_count = wdf_fn!(wdf::PFN_WDFCMRESOURCELISTGETCOUNT, WdfCmResourceListGetCountTableIndex)?;
    let get_desc = wdf_fn!(wdf::PFN_WDFCMRESOURCELISTGETDESCRIPTOR, WdfCmResourceListGetDescriptorTableIndex)?;
    let n = get_count(wdf::WdfDriverGlobals, list);
    for i in 0..n {
        let desc = get_desc(wdf::WdfDriverGlobals, list, i);
        if desc.is_null() {
            continue;
        }
        if unsafe { (*desc).Type } as u32 != wdm::CmResourceTypeInterrupt {
            continue;
        }
        let message = (unsafe { (*desc).Flags } as u32) & wdm::CM_RESOURCE_INTERRUPT_MESSAGE != 0;
        if message {
            // `MessageInterrupt.Raw.Vector` is the MSI-X table entry index the
            // bus driver assigned to this message (the *translated* Vector is
            // the IDT vector). `install` range-checks it before use.
            let raw = unsafe { (*desc).u.MessageInterrupt.__bindgen_anon_1.Raw };
            return Some((desc, true, raw.Vector, raw.MessageCount));
        }
        return Some((desc, false, 0, 0));
    }
    None
}

/// Create the one KMDF interrupt object this function needs
/// (`EvtDriverDeviceAdd`, PASSIVE_LEVEL).
///
/// No `InterruptRaw`/`InterruptTranslated` here on purpose: WDF then binds the
/// object to the device's interrupt resource at every start, which is what makes
/// `disable/enable` and `pnputil /restart-device` cycles work without the driver
/// creating and deleting interrupt objects. `MessageNumberLimit = 1` in the INF
/// means there is exactly one message, so "the device's interrupt resource" is
/// unambiguous.
///
/// Returns the `WdfInterruptCreate` status (0 = created); the handle and the
/// status are remembered in the cell because there is no log sink yet at this
/// point -- [`install`] logs them.
pub(crate) unsafe fn create(device: wdf::WDFDEVICE) -> u32 {
    let Some(cell) = (unsafe { cell_claim(device) }) else {
        dbg_line(b"irq: no free IRQ cell; the device will poll");
        return CREATE_FAILED;
    };
    unsafe {
        (*cell).interrupt = ptr::null_mut();
        (*cell).create_status = CREATE_FAILED;
        (*cell).armed.store(0, Ordering::SeqCst);
    }
    let Some(create) = wdf_fn!(wdf::PFN_WDFINTERRUPTCREATE, WdfInterruptCreateTableIndex) else {
        return CREATE_FAILED;
    };

    let mut config: wdf::WDF_INTERRUPT_CONFIG = zeroed();
    config.Size = size_of::<wdf::WDF_INTERRUPT_CONFIG>() as u32;
    // Same defaults as the WDF_INTERRUPT_CONFIG_INIT macro.
    config.ShareVector = wdf::WDF_TRI_STATE::WdfUseDefault;
    config.ReportInactiveOnPowerDown = wdf::WDF_TRI_STATE::WdfUseDefault;
    config.AutomaticSerialization = 0;
    config.PassiveHandling = 0;
    config.EvtInterruptIsr = Some(evt_interrupt_isr);
    config.EvtInterruptWorkItem = Some(evt_interrupt_work_item);

    let mut attributes: wdf::WDF_OBJECT_ATTRIBUTES = zeroed();
    attributes.Size = size_of::<wdf::WDF_OBJECT_ATTRIBUTES>() as u32;
    attributes.ParentObject = device as wdf::WDFOBJECT;

    let mut interrupt: wdf::WDFINTERRUPT = ptr::null_mut();
    let status = create(wdf::WdfDriverGlobals, device, &mut config, &mut attributes, &mut interrupt);
    if status != ST_SUCCESS || interrupt.is_null() {
        unsafe { (*cell).create_status = if status == ST_SUCCESS { CREATE_FAILED } else { status } };
        dbg_line(b"irq: WdfInterruptCreate failed");
        return unsafe { (*cell).create_status };
    }
    unsafe {
        (*cell).interrupt = interrupt;
        (*cell).create_status = 0;
    }
    0
}

/// Arm the interrupt path for this start (`EvtDevicePrepareHardware`, PASSIVE)
/// and return the value the virtqueues must write to `queue_msix_vector`.
///
/// Never fails the bring-up: any problem leaves the queues at [`NO_VECTOR`], which
/// is the 1.0.0.16 polling path.
pub(crate) unsafe fn install(
    device: wdf::WDFDEVICE,
    isr_va: *mut u8,
    num_queues: u16,
    resources_raw: wdf::WDFCMRESLIST,
    resources_translated: wdf::WDFCMRESLIST,
    log: &mut dyn virtio_media::Log,
) -> Msix {
    let mut out = Msix { vector: NO_VECTOR, installed: false };
    let Some(cell) = (unsafe { cell_for(device) }) else {
        vlog(log, format_args!("irq: no IRQ cell for this device (EvtDriverDeviceAdd missed it) -> polling"));
        return out;
    };
    unsafe { reset_stats(cell) };

    let interrupt = unsafe { (*cell).interrupt };
    if interrupt.is_null() {
        vlog(
            log,
            format_args!(
                "irq: no interrupt object (WdfInterruptCreate status 0x{:08X}) -> polling",
                unsafe { (*cell).create_status }
            ),
        );
        return out;
    }
    out.installed = true;

    // Ask WDF what it actually connected. Informational: the decision below uses
    // the raw descriptor, which is what the device indexes its MSI-X table with.
    let mut info: wdf::WDF_INTERRUPT_INFO = zeroed();
    info.Size = size_of::<wdf::WDF_INTERRUPT_INFO>() as u32;
    if let Some(get_info) = wdf_fn!(wdf::PFN_WDFINTERRUPTGETINFO, WdfInterruptGetInfoTableIndex) {
        get_info(wdf::WdfDriverGlobals, interrupt, &mut info);
    }
    vlog(
        log,
        format_args!(
            "irq: WDF info: MessageSignaled={} MessageNumber={} Vector=0x{:X} Irql={}",
            info.MessageSignaled, info.MessageNumber, info.Vector, info.Irql
        ),
    );

    let Some((_raw_desc, message, table_index, message_count)) =
        (unsafe { first_interrupt(resources_raw) })
    else {
        vlog(log, format_args!("irq: the raw resource list has no interrupt descriptor -> polling"));
        return out;
    };
    if unsafe { first_interrupt(resources_translated) }.is_none() {
        vlog(
            log,
            format_args!("irq: the translated resource list has no interrupt descriptor -> polling"),
        );
        return out;
    }
    vlog(
        log,
        format_args!(
            "irq: raw interrupt descriptor: message={} table_index={} message_count={}",
            message as u8, table_index, message_count
        ),
    );

    // `queue_msix_vector` is an index into the function's MSI-X table, and the
    // device indexes that table with it: crosvm's `MsixConfig::trigger()` panics
    // on an out-of-range entry, so refuse anything that cannot be a table entry.
    // Every implementation we run on has `num_queues + 1` entries (crosvm:
    // `num_interrupts + 1`, QEMU: `num_queues + 1`), so `index <= num_queues`
    // is the conservative test.
    let in_range = message && table_index < num_queues as u32 + 1;
    let vector = if in_range { table_index as u16 } else { NO_VECTOR };

    unsafe {
        (*cell).isr_va = isr_va;
        (*cell).message.store(message as u32, Ordering::SeqCst);
        (*cell).msix = vector;
        (*cell).armed.store(1, Ordering::SeqCst);
    }
    out.vector = vector;

    if in_range {
        vlog(
            log,
            format_args!(
                "irq: MSI-X enabled: both queues program queue_msix_vector={} (ISR status at 0x{:X})",
                vector, isr_va as usize
            ),
        );
    } else {
        vlog(
            log,
            format_args!(
                "irq: no usable MSI-X vector (message={} table_index={} num_queues={}) -> queues stay at NO_VECTOR, polling (interrupt object kept for the INTx case)",
                message as u8, table_index, num_queues
            ),
        );
    }
    out
}

/// Disarm the interrupt path for this stop (`EvtDeviceReleaseHardware`), *before*
/// the live session is dropped, so the CLOSE/MUNMAP in `LiveState::drop` runs with
/// `armed = 0` (pure polling) instead of blocking on an interrupt that is about to
/// be disconnected by the framework.
///
/// The interrupt object itself is not deleted: it belongs to the device object and
/// WDF reconnects it on the next start (see [`create`]).
pub(crate) unsafe fn release(device: wdf::WDFDEVICE, log: &mut dyn virtio_media::Log) {
    let Some(cell) = (unsafe { cell_for(device) }) else {
        return;
    };
    unsafe { (*cell).armed.store(0, Ordering::SeqCst) };
    if unsafe { (*cell).interrupt }.is_null() {
        vlog(log, format_args!("irq: release without an interrupt object (polling only)"));
        return;
    }
    log_summary(device, "release");
    unsafe {
        (*cell).isr_va = ptr::null_mut();
        (*cell).msix = NO_VECTOR;
    }
    vlog(log, format_args!("irq: interrupt path disarmed (the object stays with the device)"));
}

/// One ring-progress wait: block on the device's event with a 500 us timeout,
/// or busy-stall exactly like 1.0.0.16 when there is no interrupt to wait for.
///
/// Called instead of `KeStallExecutionProcessor(500)` from every transport wait
/// loop (`virtio_media::submit`, `reap_async`, `p1d::take_frame`, ...).
pub(crate) unsafe fn wait(device: wdf::WDFDEVICE) {
    let Some(cell) = (unsafe { cell_for(device) }) else {
        unsafe { wdm::KeStallExecutionProcessor(500) };
        return;
    };
    // Blocking is only legal at <= APC_LEVEL; every caller runs at PASSIVE, but
    // keep the guard so a future in-DPC call degrades to polling instead of
    // bugchecking.
    let can_block = unsafe { (*cell).armed.load(Ordering::SeqCst) } != 0
        && unsafe { (*cell).poll_only.load(Ordering::Relaxed) } == 0
        && unsafe { wdm::ke_get_current_irql() } <= 1;

    if !can_block {
        unsafe { (*cell).busy_stalls.fetch_add(1, Ordering::Relaxed) };
        unsafe { wdm::KeStallExecutionProcessor(500) };
        return;
    }

    unsafe { (*cell).waits.fetch_add(1, Ordering::Relaxed) };
    let mut timeout = unsafe { wdm::LARGE_INTEGER { QuadPart: WAIT_TIMEOUT_100NS } };
    let status = unsafe {
        wdm::KeWaitForSingleObject(
            (*cell).event as *mut c_void,
            wdm::KWAIT_REASON::Executive,
            wdm::MODE::KernelMode.0 as i8,
            0,
            &mut timeout as *mut wdm::LARGE_INTEGER,
        )
    } as u32;

    if status == STATUS_TIMEOUT {
        unsafe { (*cell).timeouts.fetch_add(1, Ordering::Relaxed) };
        let consecutive = unsafe { (*cell).consecutive.fetch_add(1, Ordering::Relaxed) } + 1;
        if consecutive > unsafe { (*cell).worst_dry } {
            unsafe { (*cell).worst_dry = consecutive };
        }
        if consecutive >= FALLBACK_TIMEOUTS && unsafe { (*cell).poll_only.swap(1, Ordering::SeqCst) } == 0 {
            unsafe { (*cell).fallbacks.fetch_add(1, Ordering::Relaxed) };
            // One line per episode; this is the line that tells an on-machine run
            // whether MSI-X works at all.
            let mut line = virtio_media::LineBuf::new();
            let _ = write!(
                line,
                "IRQ: {} consecutive 500 us waits without an interrupt (msi-x vector=0x{:04X}) -> polling fallback",
                consecutive,
                unsafe { (*cell).msix }
            );
            io_log_line(line.as_str());
        }
        return;
    }
    if status == 0 {
        unsafe { (*cell).wakeups.fetch_add(1, Ordering::Relaxed) };
        unsafe { (*cell).consecutive.store(0, Ordering::SeqCst) };
        return;
    }
    // STATUS_ALERTED/STATUS_USER_APC cannot happen (Alertable = FALSE); anything
    // else is unexpected, so fall back rather than spin on the same status.
    unsafe { (*cell).poll_only.store(1, Ordering::SeqCst) };
    unsafe { (*cell).fallbacks.fetch_add(1, Ordering::Relaxed) };
    unsafe { wdm::KeStallExecutionProcessor(500) };
}

/// `EVT_WDF_INTERRUPT_ISR`. Returns TRUE when the interrupt was ours, which is
/// also what tells the kernel the line was serviced.
unsafe extern "C" fn evt_interrupt_isr(interrupt: wdf::WDFINTERRUPT, _message_id: u32) -> wdf::BOOLEAN {
    let Some(cell) = (unsafe { find_cell(interrupt) }) else {
        return 0;
    };
    // A message interrupt (MSI/MSI-X) is ours by construction: the message is
    // routed to this function's one vector, and the host is *not* required to
    // set the virtio ISR byte for it -- crosvm deliberately does not ("Don't
    // need to set ISR for MSI-X interrupts"), so testing that byte here would
    // throw away every MSI-X interrupt. For legacy INTx the read is mandatory
    // (it is what deasserts the line), so claim only on a non-zero status.
    let is_message = unsafe { (*cell).message.load(Ordering::SeqCst) } != 0;
    let isr_va = unsafe { ptr::read_volatile(ptr::addr_of!((*cell).isr_va)) };
    if !is_message && !isr_va.is_null() {
        let bits = unsafe { ptr::read_volatile(isr_va) };
        if bits == 0 {
            return 0;
        }
    }
    unsafe { (*cell).irqs.fetch_add(1, Ordering::Relaxed) };
    if let Some(queue) =
        wdf_fn!(wdf::PFN_WDFINTERRUPTQUEUEWORKITEMFORISR, WdfInterruptQueueWorkItemForIsrTableIndex)
    {
        // Returns FALSE when a work item is already pending: that is fine, one
        // wakeup is enough because the waiter re-reads the used ring.
        unsafe { queue(wdf::WdfDriverGlobals, interrupt) };
    }
    1
}

/// `EVT_WDF_INTERRUPT_WORKITEM` (PASSIVE_LEVEL): wake the IOCTL thread.
unsafe extern "C" fn evt_interrupt_work_item(interrupt: wdf::WDFINTERRUPT, _associated: wdf::WDFOBJECT) {
    let Some(cell) = (unsafe { find_cell(interrupt) }) else {
        return;
    };
    if unsafe { (*cell).armed.load(Ordering::SeqCst) } == 0 {
        return;
    }
    let event = unsafe { ptr::read_volatile(ptr::addr_of!((*cell).event)) };
    if event.is_null() {
        return;
    }
    unsafe { (*cell).work_items.fetch_add(1, Ordering::Relaxed) };
    // An interrupt proves the message path works: leave the polling fallback.
    if unsafe { (*cell).poll_only.swap(0, Ordering::SeqCst) } != 0 {
        unsafe { (*cell).consecutive.store(0, Ordering::SeqCst) };
    }
    unsafe { wdm::KeSetEvent(event, 0, 0) };
}

/// One line of interrupt statistics, printed from PASSIVE_LEVEL (device ready,
/// every CLOSE, and release) so an on-machine run can tell "MSI-X works" from
/// "we are polling again" without a kernel debugger.
pub(crate) fn log_summary(device: wdf::WDFDEVICE, tag: &str) {
    let Some(cell) = (unsafe { cell_for(device) }) else {
        io_log_line("IRQ: no cell for this device");
        return;
    };
    let mut line = virtio_media::LineBuf::new();
    let _ = write!(
        line,
        "IRQ[{}] msi-x vector=0x{:04X} armed={} irqs={} work={} waits={} wakeups={} timeouts={} worst_dry={} fallbacks={} busy_stalls={}",
        tag,
        unsafe { (*cell).msix },
        unsafe { (*cell).armed.load(Ordering::SeqCst) } as u8,
        unsafe { (*cell).irqs.load(Ordering::Relaxed) },
        unsafe { (*cell).work_items.load(Ordering::Relaxed) },
        unsafe { (*cell).waits.load(Ordering::Relaxed) },
        unsafe { (*cell).wakeups.load(Ordering::Relaxed) },
        unsafe { (*cell).timeouts.load(Ordering::Relaxed) },
        unsafe { (*cell).worst_dry },
        unsafe { (*cell).fallbacks.load(Ordering::Relaxed) },
        unsafe { (*cell).busy_stalls.load(Ordering::Relaxed) },
    );
    io_log_line(line.as_str());
}
