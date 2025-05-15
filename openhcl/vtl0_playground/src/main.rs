// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Playground for VTL0.

// See build.rs.
#![cfg_attr(minimal_rt, no_std, no_main)]
// UNSAFETY: Interacting with low level hardware primitives.
#![expect(unsafe_code)]

mod arch;
mod boot_logger;
mod rt;
mod single_threaded;

fn playground_main() -> ! {
    boot_logger::boot_logger_init();

    log!("Starting up VTL0 playground...");
    loop {}
}
