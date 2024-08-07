use std::sync::atomic::{AtomicBool, Ordering};

struct Spinlock {
    lock: AtomicBool,
}

impl Spinlock {
    fn new() -> Self {
        Spinlock {
            lock: AtomicBool::new(false),
        }
    }

    fn lock(&self) {
        loop {
            let result = self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed);
            match result {
                Ok(_previous) => {
                    // We were able to change the value
                    continue;
                }
                Err(_current) => {  }
            }
        }
    }

    fn unlock(&self) {
        self.lock.store(false, Ordering::Release);
    }
}

struct SpinlockGuard {
    
}