// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(target_arch = "aarch64")]

//! aarch64 specifics.

// Entry point.
#[cfg(minimal_rt)]
core::arch::global_asm! {
    include_str!("entry.S"),
    start = sym crate::rt::start,
    relocate = sym minimal_rt::reloc::relocate,
    stack = sym crate::rt::STACK,
    STACK_COOKIE_LO = const (crate::rt::STACK_COOKIE as u16),
    STACK_COOKIE_HI = const ((crate::rt::STACK_COOKIE >> 16) as u16),
    STACK_SIZE = const crate::rt::STACK_SIZE,
}
