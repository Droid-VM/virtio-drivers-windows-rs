use core::fmt::{Write, Error};
use core::cell::UnsafeCell;

use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use spin::Spin;
use spin::mutex::spin::{SpinMutex, SpinMutexGuard};
#[cfg(target_arch = "x86_64")]
use uart_16550::SerialPort;

use crossbeam::queue::ArrayQueue;

struct TimeoutMutex<T>(SpinMutex<T>);

impl<T> TimeoutMutex<T> {
    pub const fn new(value: T) -> Self {
        Self(SpinMutex::new(value))
    }

    pub fn lock(&self) -> SpinMutexGuard<'_, T> {
        self.0.lock()
    }

    pub unsafe fn force_unlock(&self) {
        unsafe {
            self.0.force_unlock();
        }
    }

    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    pub fn try_lock(&self) -> Option<SpinMutexGuard<'_, T>> {
        self.0.try_lock()
    }

    pub fn try_lock_weak(&self) -> Option<SpinMutexGuard<'_, T>> {
        self.0.try_lock_weak()
    }

    pub fn try_lock_timeout(&self, iterations: usize) -> Option<SpinMutexGuard<'_, T>> {
        for _ in 0..5 {
            if let Some(guard) = self.try_lock_weak() {
                return Some(guard);
            }

            for _ in 0..iterations {
                if !self.is_locked() {
                    break;
                }

                core::hint::spin_loop();
            }
        }
        None
    }
}

#[repr(packed)]
struct LogEntry {
    len: u16,
    buf: [u8; 1022],
}
const _: () = assert!(size_of::<LogEntry>() == 1024);

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            len: 0,
            buf: [0; _],
        }
    }
}

impl Write for LogEntry {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        let free = &mut self.buf[self.len as usize..];
        let bytes = {
            let bytes = s.as_bytes();
            if bytes.len() <= free.len() {
                bytes
            } else {
                // Do not cut a multi-byte UTF-8 sequence in half: the entry is
                // later decoded with `from_utf8()`, and a half-written
                // character makes that fail (which used to panic with the
                // logger lock held, i.e. a panic inside the panic path).
                let mut n = free.len();
                while n > 0 && !s.is_char_boundary(n) {
                    n -= 1;
                }
                &bytes[..n]
            }
        };
        let free = &mut free[..bytes.len()];
        free.copy_from_slice(bytes);
        self.len += bytes.len() as u16;

        Ok(())
    }
}

impl LogEntry {
    fn as_str(&self) -> &str {
        let bytes = &self.buf[..self.len as usize];
        // Truncation above keeps this valid; fall back instead of panicking if
        // memory was damaged or an older writer produced garbage.
        str::from_utf8(bytes).unwrap_or("<invalid utf-8 log entry>")
    }
}

#[cfg(target_arch = "x86_64")]
type LogOutput = SerialPort;

// ARM64 has no x86 I/O ports. Send output to the Windows kernel debugger.
#[cfg(target_arch = "aarch64")]
struct LogOutput;

#[cfg(target_arch = "aarch64")]
impl Write for LogOutput {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        // DbgPrintEx transmits at most 512 bytes per call. A fixed format also
        // prevents percent signs in log messages from becoming format strings.
        for chunk in s.as_bytes().chunks(500) {
            unsafe {
                wdk::wdm::DbgPrintEx(
                    wdk::wdm::_DPFLTR_TYPE::DPFLTR_IHVVIDEO_ID.0 as _,
                    wdk::wdm::DPFLTR_ERROR_LEVEL,
                    c"%.*s".as_ptr(),
                    chunk.len() as core::ffi::c_int,
                    chunk.as_ptr().cast::<core::ffi::c_char>(),
                );
            }
        }
        Ok(())
    }
}

struct Logger {
    uart: TimeoutMutex<Option<LogOutput>>,
    msgs: Option<ArrayQueue<LogEntry>>,
}

struct GlobalLogger(UnsafeCell<Logger>);

impl GlobalLogger {
    fn replace(&self, new: Logger) -> Logger {
        // Replace will only be called once on init, so this is safe
        unsafe {
            let old = self.0.get().read();
            self.0.get().write(new);

            old
        }
    }

    fn as_logger(&self) -> &Logger {
        // There should be no more mutable references at this point
        unsafe {
            &*self.0.get()
        }
    }
}

static LOGGER: GlobalLogger = GlobalLogger(UnsafeCell::new(Logger {
    uart: TimeoutMutex::new(None),
    msgs: None,
}));

unsafe impl Sync for GlobalLogger {}

/*
pub struct LogLevelGuard(LevelFilter);

impl LogLevelGuard {
    fn new(max_level: LevelFilter) -> Self {
        let guard = Self(log::max_level());

        log::set_max_level(max_level);

        guard
    }
}

impl Drop for LogLevelGuard {
    fn drop(&mut self) {
        log::set_max_level(self.0);
    }
}

pub fn set_log_level_temp(max_level: LevelFilter) -> LogLevelGuard {
    LogLevelGuard::new(max_level)
}*/

pub fn init(max_level: LevelFilter) -> Result<(), SetLoggerError> {
    #[cfg(target_arch = "x86_64")]
    let uart = {
        let mut uart = unsafe { SerialPort::new(0x3f8) };
        uart.init();
        uart
    };
    #[cfg(target_arch = "aarch64")]
    let uart = LogOutput;

    LOGGER.replace(Logger {
        uart: TimeoutMutex::new(Some(uart)),
        msgs: Some(ArrayQueue::new(4*1024)),
    });

    log::set_logger(LOGGER.as_logger())?;
    log::set_max_level(max_level);
    Ok(())
}

pub fn deinit() {
    LOGGER.replace(Logger {
        uart: TimeoutMutex::new(None),
        msgs: None,
    });
}

pub unsafe fn force_flush() {
    // Called from the panic handler: it must never panic itself, or the
    // double panic aborts before the log (and the bugcheck parameters) are
    // emitted.
    let Some(msgs) = LOGGER.as_logger().msgs.as_ref() else {
        return;
    };

    if LOGGER.as_logger().uart.is_locked() {
        let mut uart = if let Some(uart) = LOGGER.as_logger().uart.try_lock_timeout(1_000_000) {
            uart
        } else {
            unsafe {
                LOGGER.as_logger().uart.0.force_unlock();
            }
            LOGGER.as_logger().uart.lock()
        };

        loop {
            let Some(entry) = msgs.pop() else {
                break;
            };
            let Some(uart) = uart.as_mut() else { break; };
            writeln!(
                uart,
                "[FORCE] [BUFFERED] {}",
                entry.as_str(),
            )
            .ok();
        }
    } else {
        LOGGER.as_logger().flush();
    }
}

impl Logger {
    fn try_flush(&self) {
        let Some(msgs) = self.msgs.as_ref() else {
            return;
        };
        let Some(mut guard) = self.uart.try_lock_timeout(10_000) else {
            return;
        };
        let Some(sink) = guard.as_mut() else {
            return;
        };
        let len = msgs.len();
        for _ in 0..len {
            let Some(entry) = msgs.pop() else {
                break;
            };
            writeln!(sink, "{}", entry.as_str()).ok();
        }
    }
}

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let mut entry = LogEntry::default();
        //let irql = wdk::wdm::ke_get_current_irql();
        //write!(
        //    &mut entry,
        //    "[{:02} {}] {}",
        //    irql,
        //    record.level(),
        //    record.args()
        //).unwrap();

        write!(
            &mut entry,
            "[{}] {}",
            record.level(),
            record.args()
        ).ok();

        // The logger is torn down in `deinit()`; a late log (e.g. from a
        // worker thread racing unload) must not panic.
        let Some(msgs) = self.msgs.as_ref() else {
            return;
        };
        msgs.force_push(entry);

        self.try_flush();

        /*

        let Some(mut uart) = self.uart.try_lock_timeout(100_000) else {
            let mut entry = LogEntry::default();
            write!(
                &mut entry,
                "[{}] {}",
                record.level(),
                record.args()
            ).unwrap();

            self.msgs.as_ref().unwrap().force_push(entry);

            return;
        };

        let len = self.msgs.as_ref().unwrap().len();
        for i in 0..len {
            let Some(entry) = self.msgs.as_ref().unwrap().pop() else {
                break;
            };
            writeln!(
                uart.as_mut().unwrap(),
                "{}",
                entry.as_str(),
            )
            .unwrap();
        }

        writeln!(
            uart.as_mut().unwrap(),
            "[{}] {}",
            record.level(),
            record.args()
        )
        .unwrap();
        drop(uart);

        let len = self.msgs.as_ref().unwrap().len();
        for i in 0..len {
            let Some(mut uart) = self.uart.try_lock_timeout(10_000) else {
                break;
            };
            let Some(entry) = self.msgs.as_ref().unwrap().pop() else {
                break;
            };
            writeln!(
                uart.as_mut().unwrap(),
                "{}",
                entry.as_str(),
            )
            .unwrap();
        }
        */
    }

    fn flush(&self) {
        let Some(msgs) = self.msgs.as_ref() else {
            return;
        };
        let mut guard = self.uart.lock();
        let Some(sink) = guard.as_mut() else {
            return;
        };
        let len = msgs.len();
        for _ in 0..len {
            let Some(entry) = msgs.pop() else {
                break;
            };
            writeln!(sink, "{}", entry.as_str()).ok();
        }
    }
}
