// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Playground for VTL0.

// See build.rs.
#![cfg_attr(minimal_rt, no_std, no_main)]
// UNSAFETY: Interacting with low level hardware primitives.
#![expect(unsafe_code)]

use arch::apic::apic_timer;
use arch::apic::enable_x2apic;
use arch::apic::self_ipi_x2apic;
use arch::apic::self_ipi_xapic;
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

    let tests: &[(fn(TestContext<'_>), &'static str)] = &[
        (enable_x2apic, "enable_x2apic"),
        (self_ipi_x2apic, "self_ipi_x2apic"),
        (self_ipi_xapic, "self_ipi_xapic"),
        (apic_timer, "apic_time"),
    ];

    for test in tests {
        let (test_func, test_name) = test;
        log!("Running test \"{test_name}\"");
        test_func(TestContext {
            scope: &mut Scope {
                arch: Scope::arch_init(),
                _scope: PhantomData,
                _env: PhantomData,
            },
        });
    }
    log!("Still running, line {}", line!());

    unsafe { asm!("4: sti; hlt; cli; jmp 4b") };

    verify_stack_cookie();
    match isolation {
        hvdef::HvPartitionIsolationType::NONE | hvdef::HvPartitionIsolationType::VBS => {}
        hvdef::HvPartitionIsolationType::SNP => Ghcb::uninitialize(),
        _ => unreachable!(),
    }
    loop {}
}
