// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Imports and re-exports architecture-specific implementations.

mod aarch64;
mod x86_64;

cfg_if::cfg_if!(
    if #[cfg(target_arch = "x86_64")] {
        pub use x86_64::*;
    } else if #[cfg(target_arch = "aarch64")] {
        pub use aarch64::*;
    } else {
        compile_error!("target_arch is not supported");
    }
);
