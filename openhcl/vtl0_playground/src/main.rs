// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Playground for VTL0.

// See build.rs.
#![cfg_attr(minimal_rt, no_std, no_main)]
// UNSAFETY: Interacting with low level hardware primitives.
#![expect(unsafe_code)]

use arch::apic::enable_x2apic;
use arch::scope::Scope;
use arch::scope::TestContext;
use arch::snp::Ghcb;
use core::arch::asm;
use core::marker::PhantomData;
use rt::verify_stack_cookie;

mod arch;
mod boot_logger;
mod rt;
mod single_threaded;

fn playground_main(paravisor_present: bool, isolation: hvdef::HvPartitionIsolationType) -> ! {
    match isolation {
        hvdef::HvPartitionIsolationType::NONE | hvdef::HvPartitionIsolationType::VBS => {}
        hvdef::HvPartitionIsolationType::SNP => Ghcb::initialize(),
        _ => {
            panic!("Running in unknown isolation mode: {isolation:?}");
        }
    }
    boot_logger::boot_logger_init(isolation);

    log!(
        "Starting up VTL0 playground, paravisor_present={paravisor_present}, isolation={isolation:?}"
    );

    let tctx = TestContext {
        scope: &mut Scope {
            arch: Scope::arch_init(),
            _scope: PhantomData,
            _env: PhantomData,
        },
    };
    enable_x2apic(tctx);

    log!("Still running");
    unsafe { asm!("4: sti; hlt; cli; jmp 4b") };

    verify_stack_cookie();
    match isolation {
        hvdef::HvPartitionIsolationType::NONE | hvdef::HvPartitionIsolationType::VBS => {}
        hvdef::HvPartitionIsolationType::SNP => Ghcb::uninitialize(),
        _ => unreachable!(),
    }
    loop {}
}
