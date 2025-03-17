// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

use sandi::sender_tag::SenderTag;
use sandi::tag_verifier;
use std::ffi::c_char;

use super::common::set_last_error;

#[no_mangle]
pub extern "C" fn verifier_verify_tag(
    receiver_addr: *const c_char,
    sender_tag: *const u8,
    sender_tag_len: u64,
    as_verif_key: *const u8,
    as_verif_key_len: u64,
) -> i32 {
    unsafe {
        if receiver_addr.is_null() {
            set_last_error("receiver_addr is null");
            return -1;
        }

        if sender_tag.is_null() {
            set_last_error("sender_tag is null");
            return -1;
        }

        if as_verif_key.is_null() {
            set_last_error("as_verif_key is null");
            return -1;
        }

        let receiver_addr = std::ffi::CStr::from_ptr(receiver_addr).to_str().unwrap();
        let sender_tag = std::slice::from_raw_parts(sender_tag, sender_tag_len as usize);
        let as_verif_key = std::slice::from_raw_parts(as_verif_key, as_verif_key_len as usize);

        let tag_result = SenderTag::from_slice(sender_tag);
        match tag_result {
            Ok(tag) => {
                let verif_result = tag_verifier::verify(receiver_addr, &tag, as_verif_key);
                match verif_result {
                    Ok(reputation) => {
                        return reputation as i32;
                    }
                    Err(err) => {
                        set_last_error(&err.0);
                        return -1;
                    }
                }
            }
            Err(err) => {
                set_last_error(&err);
                return -1;
            }
        }
    }
}
