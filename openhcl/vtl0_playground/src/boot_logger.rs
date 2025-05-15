// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Logging support, no TDX

#[cfg(target_arch = "x86_64")]
use crate::arch::com1::InstrIoAccess;
#[cfg(target_arch = "x86_64")]
use crate::arch::com1::Serial;
#[cfg(target_arch = "x86_64")]
use crate::single_threaded::SingleThreaded;
use core::cell::RefCell;
use core::fmt;
use core::fmt::Write;

/// The logging type to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggerType {
    Serial,
}

enum Logger {
    #[cfg(target_arch = "x86_64")]
    Serial(Serial<InstrIoAccess>),
    #[cfg(target_arch = "aarch64")]
    Serial(Serial),
    None,
}

impl Logger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self {
            Logger::Serial(serial) => serial.write_str(s),
            Logger::None => Ok(()),
        }
    }
}

pub struct BootLogger {
    logger: SingleThreaded<RefCell<Logger>>,
}

pub static BOOT_LOGGER: BootLogger = BootLogger {
    logger: SingleThreaded(RefCell::new(Logger::None)),
};

/// Initialize the boot logger. This replaces any previous init calls.
pub fn boot_logger_init() {
    let mut logger = BOOT_LOGGER.logger.borrow_mut();

    #[cfg(target_arch = "x86_64")]
    {
        *logger = Logger::Serial(Serial::init(InstrIoAccess));
    }

    #[cfg(target_arch = "aarch64")]
    {
        *logger = Logger::Serial(Serial::init());
    }
}

impl Write for &BootLogger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.logger.borrow_mut().write_str(s)
    }
}

/// Log a message. These messages are always emitted regardless of debug or
/// release, if a corresponding logger was configured.
///
/// If you want to log something just for local debugging, use [`debug_log!`]
/// instead.
#[macro_export]
macro_rules! log {
    () => {};
    ($($arg:tt)*) => {
        {
            use core::fmt::Write;
            let _ = writeln!(&$crate::boot_logger::BOOT_LOGGER, $($arg)*);
        }
    };
}

pub(crate) use log;
