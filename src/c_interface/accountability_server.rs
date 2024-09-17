use std::os::raw::c_char;

use curve25519_dalek::ristretto::CompressedRistretto;
use rand::rngs::OsRng;
use crate::accountability_server::{AccServerParams, AccountabilityServer};
use super::common::LAST_ERROR;

static mut ACC_SERVER_INSTANCE: Option<AccountabilityServer> = None;

#[no_mangle]
pub extern "C" fn as_init_acc_server(epoch_start: i64, epoch_duration: i64, tag_duration: i64, max_vks_per_epoch: i64) {
    let params = AccServerParams {
        maximum_score: 100.0,
        report_threshold: 10,
        epoch_start,
        epoch_duration: epoch_duration.try_into().unwrap(),
        tag_duration: tag_duration.try_into().unwrap(),
        max_vks_per_epoch: max_vks_per_epoch.try_into().unwrap(),
        compute_reputation: None,
        noise_distribution: None,
    };

    unsafe {
        let mut rng = OsRng;
        ACC_SERVER_INSTANCE = Some(AccountabilityServer::new(params, &mut rng));
    }
}

#[no_mangle]
pub extern "C" fn as_set_sender_epk(epk: *const u8, epk_len: u64, sender_handle: *const c_char) -> i32 {
    unsafe {
        if epk.is_null() {
            LAST_ERROR = Some("epk is null".to_owned());
            return -1;
        }

        if sender_handle.is_null() {
            LAST_ERROR = Some("sender_handle is null".to_owned());
            return -1;
        }
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };
    let epk = unsafe { std::slice::from_raw_parts(epk, epk_len.try_into().unwrap()) };

    let acc_server = unsafe { ACC_SERVER_INSTANCE.as_mut().unwrap() };
    let epk_res = CompressedRistretto::from_slice(epk).unwrap().decompress().ok_or("Failed to decompress epk");
    match epk_res {
        Ok(epk) => match acc_server.set_sender_epk(&epk, sender_handle) {
            Ok(_) => {
                return 0;
            },
            Err(err_msg) => {
                unsafe {
                    LAST_ERROR = Some(err_msg.0);
                }
                return -1;
            }
        },
        Err(err_msg) => {
            unsafe {
                LAST_ERROR = Some(err_msg.to_owned());
            }
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_issue_tag(sender_handle: *const c_char, commitment_hr: *const u8, commitment_hr_len: u64, commitment_vks: *const u8, commitment_vks_len: u64, tag: *mut u8, tag_len: u64) -> i32 {
    unsafe {
        if sender_handle.is_null() {
            LAST_ERROR = Some("sender_handle is null".to_owned());
            return -1;
        }

        if commitment_hr.is_null() {
            LAST_ERROR = Some("commitment_hr is null".to_owned());
            return -1;
        }

        if commitment_vks.is_null() {
            LAST_ERROR = Some("commitment_vks is null".to_owned());
            return -1;
        }

        if commitment_hr_len != 32 {
            LAST_ERROR = Some("commitment_hr_len is not 32".to_owned());
            return -1;
        }

        if commitment_vks_len != 32 {
            LAST_ERROR = Some("commitment_vks_len is not 32".to_owned());
            return -1;
        }

        if tag.is_null() {
            LAST_ERROR = Some("tag is null".to_owned());
            return -1;
        }

        if tag_len < 320 {
            LAST_ERROR = Some("tag_len should be at least 320".to_owned());
            return -1;
        }
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };
    let commitment_hr = unsafe { std::slice::from_raw_parts(commitment_hr, commitment_hr_len.try_into().unwrap()) };
    let commitment_vks = unsafe { std::slice::from_raw_parts(commitment_vks, commitment_vks_len.try_into().unwrap()) };
    let tag_result = unsafe { std::slice::from_raw_parts_mut(tag, tag_len.try_into().unwrap()) };

    let acc_server = unsafe { ACC_SERVER_INSTANCE.as_mut().unwrap() };

    let mut rng = OsRng;
    let issue_result = acc_server.issue_tag(commitment_hr, commitment_vks, sender_handle, &mut rng);
    match issue_result {
        Ok(tag) => {
            let tag_vec = tag.to_vec();
            if (tag_vec.len() as u64) > tag_len {
                unsafe {
                    let msg = format!("tag_len is too small: {}, required: {}", tag_len, tag_vec.len());
                    LAST_ERROR = Some(msg);
                }
                return -1;
            }
            tag_result.copy_from_slice(&tag_vec.as_slice());
            return 0;
        },
        Err(err_msg) => {
            unsafe {
                LAST_ERROR = Some(err_msg.0);
            }
            return -1;
        }
    }
}
