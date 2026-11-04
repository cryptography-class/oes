use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};

/// Overwrites `items` with their default value in a way the compiler can't
/// optimize away, even if the memory is never read again.
///
/// This only clears the memory it is given. Copies the program made earlier,
/// such as values moved on the stack or held in registers, can remain.
pub fn wipe<T: Copy + Default>(items: &mut [T]) {
    for item in items.iter_mut() {
        // SAFETY: `item` is a valid, aligned, exclusive reference, and `T: Copy`
        // means the overwritten value has no destructor that needs to run.
        unsafe { ptr::write_volatile(item, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}
