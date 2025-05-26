// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Serial output for debugging.

use core::arch::asm;
use core::fmt;

const COM1: u16 = 0x3f8;

/// Write a byte to a port.
///
/// # Safety
///
/// The caller must be sure that the given port is safe to write to, and that the
/// given value is safe for it.
unsafe fn outb(port: u16, data: u8) {
    // SAFETY: The caller has assured us this is safe.
    unsafe {
        asm! {
            "out dx, al",
            in("dx") port,
            in("al") data,
        }
    }
}

/// Read a byte from a port.
///
/// # Safety
///
/// The caller must be sure that the given port is safe to read from.
unsafe fn inb(port: u16) -> u8 {
    let mut data;
    // SAFETY: The caller has assured us this is safe.
    unsafe {
        asm! {
            "in al, dx",
            in("dx") port,
            out("al") data,
        }
    }
    data
}

/// A trait to access io ports used by the serial device.
pub trait IoAccess {
    /// Issue an in byte instruction.
    ///
    /// # Safety
    ///
    /// The caller must be sure that the given port is safe to read from.
    unsafe fn inb(&self, port: u16) -> u8;
    /// Issue an out byte instruction.
    ///
    /// # Safety
    ///
    /// The caller must be sure that the given port is safe to write to, and that the
    /// given value is safe for it.
    unsafe fn outb(&self, port: u16, data: u8);
}

/// A struct to access io ports using in/out instructions.
pub struct InstrIoAccess;

impl IoAccess for InstrIoAccess {
    unsafe fn inb(&self, port: u16) -> u8 {
        // SAFETY: The serial port caller has specified a valid port.
        unsafe { inb(port) }
    }

    unsafe fn outb(&self, port: u16, data: u8) {
        // SAFETY: The serial port caller has specified a valid port and data.
        unsafe { outb(port, data) }
    }
}

/// A writer for the COM3 UART.
pub struct Serial<T: IoAccess> {
    io: T,
}

impl<T: IoAccess> Serial<T> {
    /// Initialize the serial port.
    pub fn init(io: T) -> Self {
        // SAFETY: Writing these values to the serial device is safe.
        unsafe {
            io.outb(COM1 + 1, 0x00); // Disable all interrupts
            io.outb(COM1 + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold
            io.outb(COM1 + 4, 0x0F);
        }

        Self { io }
    }

    fn write_byte(&self, b: u8) {
        // SAFETY: Reading and writing text to the serial device is safe.
        unsafe {
            while self.io.inb(COM1 + 5) & 0x20 == 0 {}
            self.io.outb(COM1, b);
        }
    }
}

impl<T: IoAccess> fmt::Write for Serial<T> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
        Ok(())
    }
}
