// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Support for working with global variables in a single-threaded environment.
//! In such an environment, it is safe to access globals even if they don't
//! implement [`Sync`], since there is only one thread that can access them. But
//! code still needs to be careful to avoid creating multiple _mutable_
//! references to the same global. These types provide abstractions for doing
//! this safely.

#![allow(dead_code)]

use core::cell::Cell;
use core::cell::UnsafeCell;
use core::ops::Deref;
use core::ops::DerefMut;

/// A wrapper around a value that implements `Sync` even if `T` does not
/// implement `Sync`.
///
/// This is only safe to use in a single-threaded environment. Do not compile
/// this type into a multi-threaded environment.
pub struct SingleThreaded<T>(pub T);

// SAFETY: we must mark this as Sync so that it can be `static`. It is
// not actually necessarily Sync, so this can only be used in a
// single-threaded environment.
unsafe impl<T> Sync for SingleThreaded<T> {}

impl<T> Deref for SingleThreaded<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// A reference returned by [`off_stack`].
pub struct OffStackRef<'a, T>(&'a mut T, BorrowRef<'a>);

impl<'a, T> OffStackRef<'a, T> {
    #[track_caller]
    #[doc(hidden)]
    pub unsafe fn new_internal(value: &'a UnsafeCell<T>, used: &'a Cell<bool>) -> Self {
        let r = BorrowRef::try_new(used).expect("function recursed");
        // SAFETY: we just set `used` to true, so we know that we are the only
        // one accessing `value`.
        let value = unsafe { &mut *value.get() };
        OffStackRef(value, r)
    }

    /// Leaks the borrow, returning the reference.
    ///
    /// This will lead to a panic if there is an attempt to borrow the value
    /// again (e.g., if the function invoking the `off_stack` macro is called
    /// again).
    pub fn leak(this: Self) -> &'a mut T {
        core::mem::forget(this.1);
        this.0
    }
}

struct BorrowRef<'a>(&'a Cell<bool>);

impl<'a> BorrowRef<'a> {
    fn try_new(used: &'a Cell<bool>) -> Option<Self> {
        if used.replace(true) {
            None
        } else {
            Some(Self(used))
        }
    }
}

impl Drop for BorrowRef<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

impl<T> Deref for OffStackRef<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0
    }
}

impl<T> DerefMut for OffStackRef<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}
