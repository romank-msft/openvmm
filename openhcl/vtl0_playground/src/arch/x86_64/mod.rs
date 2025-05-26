// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "x86_64")]

//! x86_64 architecture-specific implementations.

pub mod com_port;
pub mod snp;

// Entry point.
#[cfg(minimal_rt)]
core::arch::global_asm! {
    include_str!("entry.S"),
    relocate = sym minimal_rt::reloc::relocate,
    start = sym crate::rt::start,
    stack = sym crate::rt::STACK,
    STACK_COOKIE = const crate::rt::STACK_COOKIE,
    STACK_SIZE = const crate::rt::STACK_SIZE,
}
