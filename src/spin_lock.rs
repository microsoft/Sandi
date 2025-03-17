// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

pub(crate) struct Spinlock {
    lock: AtomicBool,
}

impl Spinlock {
    pub(crate) fn new() -> Self {
        Spinlock {
            lock: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        loop {
            let result =
                self.lock
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
            match result {
                Ok(_previous) => {
                    // We were able to change the value
                    return;
                }
                Err(_current) => {}
            }
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

pub(crate) struct SpinlockGuard {
    lock: Arc<Spinlock>,
}

impl SpinlockGuard {
    pub(crate) fn new(lock: Arc<Spinlock>) -> Self {
        lock.lock();
        SpinlockGuard { lock }
    }
}

impl Drop for SpinlockGuard {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_spinlock() {
        let spinlock = Arc::new(Spinlock::new());
        let guard = SpinlockGuard::new(spinlock.clone());
        drop(guard);
        let guard = SpinlockGuard::new(spinlock.clone());
        drop(guard);
    }

    #[test]
    fn test_spinlock_concurrent() {
        let time_start = std::time::Instant::now();
        let spinlock = Arc::new(Spinlock::new());
        let spinlock_clone = spinlock.clone();
        let handle = std::thread::spawn(move || {
            let guard = SpinlockGuard::new(spinlock_clone);
            std::thread::sleep(std::time::Duration::from_secs(1));
            drop(guard);
        });
        let guard = SpinlockGuard::new(spinlock.clone());
        std::thread::sleep(std::time::Duration::from_secs(1));
        drop(guard);
        handle.join().unwrap();
        let time_end = std::time::Instant::now();
        let elapsed = time_end - time_start;
        // The total time should be around 2 seconds
        assert!(elapsed.as_millis() > 1750);
    }
}
