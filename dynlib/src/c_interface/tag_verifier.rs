use std::ffi::c_char;
use acctblty::tag_verifier;
use acctblty::sender_tag::SenderTag;

use super::common::LAST_ERROR;


#[no_mangle]
pub extern "C" fn verifier_verify_tag(receiver_addr: *const c_char, sender_tag: *const u8, sender_tag_len: u64, as_verif_key: *const u8, as_verif_key_len: u64) -> i32 {
    unsafe {
        if receiver_addr.is_null() {
            LAST_ERROR = Some("receiver_addr is null".to_string());
            return -1;
        }

        if sender_tag.is_null() {
            LAST_ERROR = Some("sender_tag is null".to_string());
            return -1;
        }

        if as_verif_key.is_null() {
            LAST_ERROR = Some("as_verif_key is null".to_string());
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
                        LAST_ERROR = Some(err.0);
                        return -1;
                    }
                }
            },
            Err(err) => {
                LAST_ERROR = Some(err.to_string());
                return -1;
            }
        }
    }
}
