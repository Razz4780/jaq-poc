//! Memory shared between the service and the workers.
//!
//! - The **input arena**: one `memfd`, created before the dispatcher is forked. The service maps
//!   it read-write and encodes inputs into it; the dispatcher maps it read-only, so every worker
//!   inherits a read-only view of the same pages. An input encoded once can be read by any
//!   number of workers, and nothing is copied to hand it over.
//! - A **progress page** per worker, created by the dispatcher for each worker it forks. The
//!   worker records in it which filter of a batch it is running and the verdicts it has reached,
//!   so that when it dies the service knows which filter killed it and which verdicts stand.
//!
//! The read-only view is opened through `/proc/self/fd` with `O_RDONLY`, so the kernel refuses
//! to make it writable later, `mprotect` included.

use std::{
    collections::BTreeMap,
    fs::File,
    io,
    num::NonZeroUsize,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    ptr::NonNull,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU8, AtomicU32, Ordering},
    },
};

use nix::{
    sys::{
        memfd::{MFdFlags, memfd_create},
        mman::{MapFlags, MmapAdvise, ProtFlags, madvise, mmap, munmap},
    },
    unistd::ftruncate,
};

/// A shared mapping of a `memfd`, unmapped on drop.
#[derive(Debug)]
pub struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}

// Safety: the mapping is plain memory. Every access goes through raw pointers or atomics, and the
// protocol around each region says who may write it when.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    pub fn new(fd: BorrowedFd<'_>, len: usize, writable: bool) -> io::Result<Self> {
        let length = NonZeroUsize::new(len).ok_or(io::ErrorKind::InvalidInput)?;
        let prot = if writable {
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE
        } else {
            ProtFlags::PROT_READ
        };
        // Safety: a new shared mapping of a file, placed by the kernel, aliases no Rust object.
        let ptr = unsafe { mmap(None, length, prot, MapFlags::MAP_SHARED, fd, 0) }?;
        Ok(Self {
            ptr: ptr.cast(),
            len,
        })
    }

    /// Maps `fd` read-only, through a descriptor that is itself read-only.
    pub fn read_only(fd: BorrowedFd<'_>, len: usize) -> io::Result<Self> {
        let read_only = File::open(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
        Self::new(read_only.as_fd(), len, false)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // Safety: the mapping was created by `mmap` with this length and is unmapped only here.
        let _ = unsafe { munmap(self.ptr.cast(), self.len) };
    }
}

pub fn create(name: &std::ffi::CStr, len: usize) -> io::Result<OwnedFd> {
    let fd = memfd_create(name, MFdFlags::MFD_CLOEXEC)?;
    ftruncate(
        &fd,
        len.try_into().map_err(|_| io::ErrorKind::InvalidInput)?,
    )?;
    Ok(fd)
}

/// Alignment of inputs in the arena.
const ALIGN: usize = 64;
/// Pages of the arena below this offset stay resident once touched. Pages above it are given back
/// to the kernel when the input on them is freed, so that a burst of large inputs does not stay
/// resident for the life of the service. Allocation is first fit, so the bottom of the arena is
/// where inputs usually go, and giving those pages back each time would cost a page fault per
/// page on the next input.
const RESIDENT: usize = 4 << 20;
const PAGE: usize = 4096;

/// The service's side of the input arena: a first-fit allocator over the shared mapping.
#[derive(Debug)]
pub struct Arena {
    map: Mapping,
    /// Free ranges, offset to length, never adjacent to each other.
    free: Mutex<BTreeMap<usize, usize>>,
}

impl Arena {
    pub fn new(map: Mapping) -> Self {
        let free = BTreeMap::from([(0, map.len())]);
        Self {
            map,
            free: Mutex::new(free),
        }
    }

    /// Copies `bytes` into the arena. `None` if there is no room for them right now.
    pub fn alloc(self: &Arc<Self>, bytes: &[u8]) -> Option<Slot> {
        let capacity = bytes.len().max(1).checked_next_multiple_of(ALIGN)?;
        let offset = {
            let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
            let (&offset, &len) = free.iter().find(|(_, len)| **len >= capacity)?;
            free.remove(&offset);
            if len > capacity {
                free.insert(offset + capacity, len - capacity);
            }
            offset
        };
        // Safety: `offset..offset + capacity` lies in the mapping and was free, so no worker
        // reads it and no other slot covers it. The service's mapping is writable.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.map.ptr().add(offset), bytes.len());
        }
        Some(Slot {
            arena: self.clone(),
            offset,
            len: bytes.len(),
            capacity,
        })
    }

    fn release(&self, offset: usize, capacity: usize) {
        let (mut start, mut len) = (offset, capacity);
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((&before, &before_len)) = free.range(..start).next_back()
            && before + before_len == start
        {
            free.remove(&before);
            (start, len) = (before, before_len + len);
        }
        if let Some(after_len) = free.remove(&(start + len)) {
            len += after_len;
        }
        free.insert(start, len);
        drop(free);

        let first = offset.max(RESIDENT).next_multiple_of(PAGE);
        let last = (offset + capacity) / PAGE * PAGE;
        if last > first {
            // Safety: the pages lie in the freed range, which no slot covers any more, and
            // `MADV_REMOVE` only drops their contents.
            let _ = unsafe {
                madvise(
                    NonNull::new_unchecked(self.map.ptr().add(first)).cast(),
                    last - first,
                    MmapAdvise::MADV_REMOVE,
                )
            };
        }
    }
}

/// An encoded input in the arena. The range is never written while the slot exists, and is
/// returned to the arena when it is dropped.
#[derive(Debug)]
pub struct Slot {
    arena: Arc<Arena>,
    offset: usize,
    len: usize,
    capacity: usize,
}

impl Slot {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_in(&self, arena: &Arc<Arena>) -> bool {
        Arc::ptr_eq(&self.arena, arena)
    }

    pub fn bytes(&self) -> &[u8] {
        // Safety: the range lies in the mapping and is not written while the slot exists.
        unsafe { std::slice::from_raw_parts(self.arena.map.ptr().add(self.offset), self.len) }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.arena.release(self.offset, self.capacity);
    }
}

/// A worker's read-only view of the arena.
pub struct ArenaView(Mapping);

impl ArenaView {
    pub fn new(map: Mapping) -> Self {
        Self(map)
    }

    /// The input at `offset..offset + len`, or `None` if that is not inside the arena.
    ///
    /// # Safety
    ///
    /// The service must not write the range for as long as the returned value exists. It does
    /// not: the range belongs to a [`Slot`] that the request keeps alive until the worker has
    /// replied or is dead, and the worker drops the value before it replies.
    pub unsafe fn input(&self, offset: usize, len: usize) -> Option<ArenaInput> {
        let end = offset.checked_add(len)?;
        (end <= self.0.len()).then(|| ArenaInput {
            // Safety: in bounds, checked above.
            ptr: unsafe { self.0.ptr().add(offset) },
            len,
        })
    }
}

/// An input in the arena, as a worker sees it.
pub struct ArenaInput {
    ptr: *const u8,
    len: usize,
}

impl AsRef<[u8]> for ArenaInput {
    fn as_ref(&self) -> &[u8] {
        // Safety: see `ArenaView::input`. The mapping lives as long as the worker.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Layout of a progress page.
pub const PAGE_LEN: usize = PAGE;
const VERDICTS_AT: usize = 8;
/// The most filters one request can carry: one verdict byte each.
pub const MAX_BATCH: usize = PAGE_LEN - VERDICTS_AT;

/// A verdict in a progress page.
pub mod verdict {
    pub const FALSE: u8 = 0;
    pub const TRUE: u8 = 1;
    pub const INVALID_FILTER: u8 = 2;
}

/// A worker's progress page. The worker writes it; the service reads it once the worker has
/// replied or died.
#[derive(Debug)]
pub struct Progress(Mapping);

impl Progress {
    pub fn new(map: Mapping) -> io::Result<Self> {
        if map.len() < PAGE_LEN {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(map))
    }

    fn started_counter(&self) -> &AtomicU32 {
        // Safety: the mapping is page-aligned and at least a page long, and the first four bytes
        // are only ever accessed as this atomic.
        unsafe { &*self.0.ptr().cast::<AtomicU32>() }
    }

    fn verdict_slot(&self, index: usize) -> Option<&AtomicU8> {
        (index < MAX_BATCH).then(|| {
            // Safety: in bounds, and verdict bytes are only ever accessed as atomics.
            unsafe { &*self.0.ptr().add(VERDICTS_AT + index).cast::<AtomicU8>() }
        })
    }

    /// How many filters of the current request have started.
    pub fn started(&self) -> usize {
        self.started_counter().load(Ordering::Acquire) as usize
    }

    pub fn start(&self, index: usize) {
        self.started_counter()
            .store(index as u32 + 1, Ordering::Release);
    }

    pub fn reset(&self) {
        self.started_counter().store(0, Ordering::Release);
    }

    pub fn set_verdict(&self, index: usize, verdict: u8) {
        if let Some(slot) = self.verdict_slot(index) {
            slot.store(verdict, Ordering::Release);
        }
    }

    pub fn verdict(&self, index: usize) -> Option<u8> {
        self.verdict_slot(index)
            .map(|slot| slot.load(Ordering::Acquire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arena(len: usize) -> Arc<Arena> {
        let fd = create(c"test", len).unwrap();
        Arc::new(Arena::new(Mapping::new(fd.as_fd(), len, true).unwrap()))
    }

    #[test]
    fn alloc_and_coalesce() {
        let arena = arena(4 * ALIGN);
        let a = arena.alloc(&[1; 10]).unwrap();
        let b = arena.alloc(&[2; ALIGN + 1]).unwrap();
        assert!(arena.alloc(&[3; 2 * ALIGN]).is_none());
        let c = arena.alloc(&[4; 1]).unwrap();
        assert_eq!((a.offset(), b.offset(), c.offset()), (0, ALIGN, 3 * ALIGN));
        assert_eq!(b.bytes(), &[2; ALIGN + 1]);
        drop(a);
        drop(b);
        // The two freed ranges merged.
        let d = arena.alloc(&[5; 3 * ALIGN]).unwrap();
        assert_eq!(d.offset(), 0);
        drop((c, d));
        assert_eq!(arena.free.lock().unwrap().len(), 1);
    }

    #[test]
    fn read_only_view() {
        let fd = create(c"test", PAGE).unwrap();
        let writable = Mapping::new(fd.as_fd(), PAGE, true).unwrap();
        let view = ArenaView::new(Mapping::read_only(fd.as_fd(), PAGE).unwrap());
        unsafe { *writable.ptr().add(5) = 42 };
        let input = unsafe { view.input(5, 1) }.unwrap();
        assert_eq!(input.as_ref(), &[42]);
        assert!(unsafe { view.input(PAGE, 1) }.is_none());

        // The view cannot be made writable.
        let made_writable = unsafe {
            nix::sys::mman::mprotect(
                view.0.ptr.cast(),
                PAGE,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
        };
        assert!(made_writable.is_err());
    }
}
