//! Peak memory measurement.
//!
//! Counts heap allocations instead of asking the operating system, so it works
//! the same on every platform without extra dependencies. It covers the
//! program's heap only, not the stack or the executable itself.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system allocator plus counters. Installed in `main.rs`.
pub struct CountingAllocator;

fn record_growth(bytes: usize) {
    let current = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(current, Ordering::Relaxed);
}

fn record_shrink(bytes: usize) {
    CURRENT.fetch_sub(bytes, Ordering::Relaxed);
}

/// Returns the most heap memory in use at once since the program started, in bytes.
pub fn peak_heap_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

// SAFETY: every call is forwarded unchanged to `System`, which upholds the
// `GlobalAlloc` contract. The counters don't allocate or touch the memory.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantees about `layout` are passed on unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_growth(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's guarantees about `layout` are passed on unchanged.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record_growth(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's guarantees about `ptr` and `layout` are passed on unchanged.
        unsafe { System.dealloc(ptr, layout) };
        record_shrink(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's guarantees about all arguments are passed on unchanged.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                record_growth(new_size - layout.size());
            } else {
                record_shrink(layout.size() - new_size);
            }
        }
        new_ptr
    }
}
