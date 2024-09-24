use std::{ffi::CStr, os::raw::c_char};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{rngs::OsRng, RngCore};
use crate::{sender::Sender, tag::Tag};
use super::common::LAST_ERROR;

static mut SENDER_INSTANCE: Option<Sender> = None;

#[no_mangle]
pub extern "C" fn sender_init_sender(handle: *const c_char) -> i32 {
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

#[no_mangle]
pub extern "C" fn sender_add_channel(receiver_addr: *const c_char, vks: *mut u8, vks_len: u64, sks: *mut u8, sks_len: u64) -> i32 {
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

#[no_mangle]
pub extern "C" fn sender_generate_new_epoch_keys() -> i32 {
    unsafe {
        if SENDER_INSTANCE.is_none() {
            LAST_ERROR = Some("SENDER is not initialized".to_owned());
            return -1;
        }

        let sender = SENDER_INSTANCE.as_mut().unwrap();
        let mut rng = OsRng;

        sender.generate_new_epoch_keys(&mut rng);

        return 0;
    }
}

#[no_mangle]
pub extern "C" fn sender_get_public_epoch_key(epk: *mut u8, epk_len: u64) -> i32 {
    unsafe {
        if SENDER_INSTANCE.is_none() {
            LAST_ERROR = Some("SENDER is not initialized".to_owned());
            return -1;
        }

        let sender = SENDER_INSTANCE.as_mut().unwrap();
        let epk_comp = sender.epk.compress();
        let bytes = epk_comp.as_bytes();

        if epk.is_null() {
            return bytes.len() as i32;
        }

        if epk_len < bytes.len().try_into().unwrap() {
            let msg = format!("epk_len is not at least {}", bytes.len());
            LAST_ERROR = Some(msg);
            return -1;
        }

        let epk_slice = std::slice::from_raw_parts_mut(epk, bytes.len());
        epk_slice.copy_from_slice(bytes);

        return bytes.len() as i32;
    }
}

#[no_mangle]
pub extern "C" fn sender_get_commitments(receiver_addr: *const c_char, vks: *const u8, vks_len: u64, commitment_hr: *mut u8, commitment_hr_len: u64, commitment_vks: *mut u8, commitment_vks_len: u64, randomness_hr: *mut u8, randomness_hr_len: u64, randomness_vks: *mut u8, randomness_vks_len: u64) -> i32 {
    unsafe {
        if receiver_addr.is_null() {
            LAST_ERROR = Some("receiver_addr is null".to_owned());
            return -1;
        }

        if vks.is_null() {
            LAST_ERROR = Some("vks is null".to_owned());
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

        if commitment_hr_len < 32 {
            LAST_ERROR = Some("commitment_hr_len is not at least 32".to_owned());
            return -1;
        }

        if commitment_vks_len < 32 {
            LAST_ERROR = Some("commitment_vks_len is not at least 32".to_owned());
            return -1;
        }

        if randomness_hr.is_null() {
            LAST_ERROR = Some("randomness_hr is null".to_owned());
            return -1;
        }

        if randomness_vks.is_null() {
            LAST_ERROR = Some("randomness_vks is null".to_owned());
            return -1;
        }

        if randomness_hr_len < 32 {
            LAST_ERROR = Some("randomness_hr_len is not at least 32".to_owned());
            return -1;
        }

        if randomness_vks_len < 32 {
            LAST_ERROR = Some("randomness_vks_len is not at least 32".to_owned());
            return -1;
        }

        let receiver_addr = CStr::from_ptr(receiver_addr).to_str().unwrap();
        let vks_slice = std::slice::from_raw_parts(vks, vks_len.try_into().unwrap());
        let commitment_hr_slice = std::slice::from_raw_parts_mut(commitment_hr, commitment_hr_len.try_into().unwrap());
        let commitment_vks_slice = std::slice::from_raw_parts_mut(commitment_vks, commitment_vks_len.try_into().unwrap());
        let randomness_hr_slice = std::slice::from_raw_parts_mut(randomness_hr, randomness_hr_len.try_into().unwrap());
        let randomness_vks_slice = std::slice::from_raw_parts_mut(randomness_vks, randomness_vks_len.try_into().unwrap());

        let mut rnd_hr = [0u8; 32];
        let mut rnd_vks = [0u8; 32];

        let mut rng = OsRng;
        rng.fill_bytes(&mut rnd_hr);
        rng.fill_bytes(&mut rnd_vks);

        let mut mac = Hmac::<Sha256>::new_from_slice(&rnd_hr).unwrap();
        mac.update(receiver_addr.as_bytes());
        let cmtmt_hr = mac.finalize();

        let mut mac = Hmac::<Sha256>::new_from_slice(&rnd_vks).unwrap();
        mac.update(vks_slice);
        let cmtmt_vks = mac.finalize();

        commitment_hr_slice.copy_from_slice(cmtmt_hr.into_bytes().as_slice());
        commitment_vks_slice.copy_from_slice(cmtmt_vks.into_bytes().as_slice());
        randomness_hr_slice.copy_from_slice(rnd_hr.as_ref());
        randomness_vks_slice.copy_from_slice(rnd_vks.as_ref());
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn sender_issue_tag(as_tag: *const u8, as_tag_len: u64, randomness_hr: *const u8, randomness_hr_len: u64, randomness_vks: *const u8, randomness_vks_len: u64, vks: *const u8, vks_len: u64, sender_tag: *mut u8, sender_tag_len: u64) -> i32 {
    unsafe {
        if SENDER_INSTANCE.is_none() {
            LAST_ERROR = Some("SENDER is not initialized".to_owned());
            return -1;
        }

        if as_tag.is_null() {
            LAST_ERROR = Some("as_tag is null".to_owned());
            return -1;
        }

        if randomness_hr.is_null() {
            LAST_ERROR = Some("randomness_hr is null".to_owned());
            return -1;
        }

        if randomness_vks.is_null() {
            LAST_ERROR = Some("randomness_vks is null".to_owned());
            return -1;
        }

        if vks.is_null() {
            LAST_ERROR = Some("vks is null".to_owned());
            return -1;
        }

        if as_tag_len < 32 {
            LAST_ERROR = Some("as_tag_len is not at least 32".to_owned());
            return -1;
        }

        if randomness_hr_len < 32 {
            LAST_ERROR = Some("randomness_hr_len is not at least 32".to_owned());
            return -1;
        }

        if randomness_vks_len < 32 {
            LAST_ERROR = Some("randomness_vks_len is not at least 32".to_owned());
            return -1;
        }

        if vks_len < 32 {
            LAST_ERROR = Some("vks_len is not at least 32".to_owned());
            return -1;
        }

        if sender_tag.is_null() {
            LAST_ERROR = Some("sender_tag is null".to_owned());
            return -1;
        }

        if sender_tag_len < 320 {
            LAST_ERROR = Some("sender_tag_len should be at least 320".to_owned());
            return -1;
        }

        let as_tag_slice = std::slice::from_raw_parts(as_tag, as_tag_len.try_into().unwrap());
        let randomness_hr_slice = std::slice::from_raw_parts(randomness_hr, randomness_hr_len.try_into().unwrap());
        let randomness_vks_slice = std::slice::from_raw_parts(randomness_vks, randomness_vks_len.try_into().unwrap());
        let vks_slice = std::slice::from_raw_parts(vks, vks_len.try_into().unwrap());
        let sender_tag_slice = std::slice::from_raw_parts_mut(sender_tag, sender_tag_len.try_into().unwrap());

        let tag_result = Tag::from_slice(as_tag_slice);
        let mut rng = OsRng;

        match tag_result {
            Ok(tag) => {
                let sender = SENDER_INSTANCE.as_mut().unwrap();
                let result = sender.get_tag_from_as_tag(
                    tag,
                    randomness_hr_slice.try_into().unwrap(),
                    randomness_vks_slice.try_into().unwrap(),
                    vks_slice,
                    &mut rng);
                match result {
                    Ok(sender_tag) => {
                        let sender_tag_buff = sender_tag.to_vec();
                        let test = crate::sender_tag::SenderTag::from_slice(sender_tag_buff.as_slice());
                        assert!(test.is_ok());
                        if sender_tag_buff.len() as u64 > sender_tag_len {
                            LAST_ERROR = Some(format!("sender_tag_len is too small: {}, required: {}", sender_tag_len, sender_tag_buff.len()));
                            return -1;
                        }

                        sender_tag_slice.copy_from_slice(sender_tag_buff.as_slice());
                        return 0;
                    },
                    Err(e) => {
                        LAST_ERROR = Some(format!("Error issuing tag: {}", e.0));
                        return -1;
                    }
                }
            }
            Err(e) => {
                LAST_ERROR = Some(format!("Error reading AS tag: {}", e.to_string()));
                return -1;
            }
        }
    }
}
