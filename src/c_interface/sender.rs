use std::{ffi::CStr, os::raw::c_char};
use rand::rngs::OsRng;
use crate::sender::Sender;
use super::common::LAST_ERROR;

static mut SENDER_INSTANCE: Option<Sender> = None;

pub extern "C" fn init_sender(handle: *const c_char) -> i32 {
    unsafe {
        if handle.is_null() {
            LAST_ERROR = Some("handle is null".to_owned());
            return -1;
        }

        let handle_str = CStr::from_ptr(handle).to_str().unwrap();
        let mut rng = OsRng;

        let sender = Sender::new(handle_str, &mut rng);
        SENDER_INSTANCE = Some(sender);
    }

    return 0;
}

pub extern "C" fn add_channel(receiver_addr: *const c_char, vks: *mut u8, vks_len: u64, sks: *mut u8, sks_len: u64) -> i32 {
    unsafe {
        if receiver_addr.is_null() {
            LAST_ERROR = Some("receiver_addr is null".to_owned());
            return -1;
        }

        if vks.is_null() {
            LAST_ERROR = Some("vks is null".to_owned());
            return -1;
        }

        if sks.is_null() {
            LAST_ERROR = Some("sks is null".to_owned());
            return -1;
        }

        if vks_len < 32 {
            LAST_ERROR = Some("vks_len is not at least 32".to_owned());
            return -1;
        }

        if sks_len < 32 {
            LAST_ERROR = Some("sks_len is not at least 32".to_owned());
            return -1;
        }

        if SENDER_INSTANCE.is_none() {
            LAST_ERROR = Some("SENDER is not initialized".to_owned());
            return -1;
        }

        let receiver_addr = CStr::from_ptr(receiver_addr).to_str().unwrap();

        let sender = SENDER_INSTANCE.as_mut().unwrap();
        let mut rng = OsRng;

        let result = sender.add_channel(receiver_addr, &mut rng);

        // Copy result to vks
        let vks_slice = std::slice::from_raw_parts_mut(vks, 32);
        vks_slice.copy_from_slice(result.vks.compress().as_bytes());
        let sks_slice = std::slice::from_raw_parts_mut(sks, 32);
        sks_slice.copy_from_slice(result.sks.as_bytes());

        return 0;
    }
}