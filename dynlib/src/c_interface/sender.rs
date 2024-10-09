use std::{collections::HashMap, ffi::CStr, os::raw::c_char};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::{rngs::OsRng, RngCore};
use acctblty::{sender::Sender, sender_tag::SenderTag, tag::Tag};
use super::common::set_last_error;

static mut SENDER_INSTANCES: Option<HashMap<u64, Sender>> = None;

struct SenderInstError(pub String);

fn get_sender_mut_ref(sender_id: u64) -> Result<&'static mut Sender, SenderInstError> {
    unsafe {
        if SENDER_INSTANCES.is_none() {
            return Err(SenderInstError("SENDER_INSTANCES is not initialized".to_string()));
        }

        let senders = SENDER_INSTANCES.as_mut().unwrap();
        match senders.get_mut(&sender_id) {
            Some(sender) => Ok(sender),
            None => Err(SenderInstError("Sender not found".to_string()))
        }
    }
}

fn get_sender_ref(server_id: u64) -> Result<&'static Sender, SenderInstError> {
    unsafe {
        if SENDER_INSTANCES.is_none() {
            return Err(SenderInstError("SERVER is not initialized".to_string()));
        }

        let senders = SENDER_INSTANCES.as_mut().unwrap();
        match senders.get(&server_id) {
            Some(sender) => Ok(sender),
            None => Err(SenderInstError("Server not found".to_string()))
        }
    }
}

fn add_sender_instance(sender_id: u64, sender: Sender) {
    unsafe {
        if SENDER_INSTANCES.is_none() {
            SENDER_INSTANCES = Some(HashMap::new());
        }

        let senders = SENDER_INSTANCES.as_mut().unwrap();
        senders.insert(sender_id, sender);
    }
}

#[no_mangle]
pub extern "C" fn sender_init_sender(handle: *const c_char, sender_id: *mut u64) -> i32 {
    unsafe {
        if handle.is_null() {
            set_last_error("handle is null");
            return -1;
        }

        if sender_id.is_null() {
            set_last_error("sender_id is null");
            return -1;
        }

        let handle_str = CStr::from_ptr(handle).to_str().unwrap();
        let mut rng = OsRng;

        let sender = Sender::new(handle_str, &mut rng);
        let sdr_id = rng.next_u64();

        add_sender_instance(sdr_id, sender);
        *sender_id = sdr_id;

        return 0;
    }
}

#[no_mangle]
pub extern "C" fn sender_add_channel(sender_id: u64, receiver_addr: *const c_char, vks: *mut u8, vks_len: u64, sks: *mut u8, sks_len: u64) -> i32 {
    unsafe {
        if receiver_addr.is_null() {
            set_last_error("receiver_addr is null");
            return -1;
        }

        if vks.is_null() {
            set_last_error("vks is null");
            return -1;
        }

        if sks.is_null() {
            set_last_error("sks is null");
            return -1;
        }

        if vks_len < 32 {
            set_last_error("vks_len is not at least 32");
            return -1;
        }

        if sks_len < 32 {
            set_last_error("sks_len is not at least 32");
            return -1;
        }

        let receiver_addr = CStr::from_ptr(receiver_addr).to_str().unwrap();

        let sender = match get_sender_mut_ref(sender_id) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e.0);
                return -1;
            }
        };

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
pub extern "C" fn sender_get_channel_count(sender_id: u64, receiver_handle: *const c_char) -> i32 {
    unsafe {
        if receiver_handle.is_null() {
            set_last_error("receiver_handle is null");
            return -1;
        }

        let receiver_handle = CStr::from_ptr(receiver_handle).to_str().unwrap();

        let sender = match get_sender_ref(sender_id) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e.0);
                return -1;
            }
        };

        let channels = sender.get_channels(receiver_handle);
        return channels.len() as i32;
    }
}

#[no_mangle]
pub extern "C" fn sender_get_channel(sender_id: u64, receiver_handle: *const c_char, channel_idx: u64, vks: *mut u8, vks_len: u64, sks: *mut u8, sks_len: u64) -> i32 {
    unsafe {
        if receiver_handle.is_null() {
            set_last_error("receiver_handle is null");
            return -1;
        }

        if vks.is_null() {
            set_last_error("vks is null");
            return -1;
        }

        if sks.is_null() {
            set_last_error("sks is null");
            return -1;
        }

        if vks_len < 32 {
            set_last_error("vks_len is not at least 32");
            return -1;
        }

        if sks_len < 32 {
            set_last_error("sks_len is not at least 32");
            return -1;
        }

        let receiver_handle = CStr::from_ptr(receiver_handle).to_str().unwrap();

        let sender = match get_sender_ref(sender_id) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e.0);
                return -1;
            }
        };

        let channels = sender.get_channels(receiver_handle);
        if channel_idx >= channels.len() as u64 {
            set_last_error(&format!("Channel index out of bounds: {}", channel_idx));
            return -1;
        }

        let channel = channels[channel_idx as usize];
        let vks_slice = std::slice::from_raw_parts_mut(vks, 32);
        vks_slice.copy_from_slice(channel.vks.compress().as_bytes());
        let sks_slice = std::slice::from_raw_parts_mut(sks, 32);
        sks_slice.copy_from_slice(channel.sks.as_bytes());

        return 0;
    }
}

#[no_mangle]
pub extern "C" fn sender_generate_new_epoch_keys(sender_id: u64) -> i32 {
    let sender = match get_sender_mut_ref(sender_id) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&e.0);
            return -1;
        }
    };

    let mut rng = OsRng;

    sender.generate_new_epoch_keys(&mut rng);

    return 0;
}

#[no_mangle]
pub extern "C" fn sender_get_public_epoch_key(sender_id: u64, epk: *mut u8, epk_len: u64) -> i32 {
    unsafe {
        let sender = match get_sender_ref(sender_id) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e.0);
                return -1;
            }
        };

        let epk_comp = sender.epk.compress();
        let bytes = epk_comp.as_bytes();

        if epk.is_null() {
            return bytes.len() as i32;
        }

        if epk_len < bytes.len().try_into().unwrap() {
            let msg = format!("epk_len is not at least {}", bytes.len());
            set_last_error(&msg);
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
            set_last_error("receiver_addr is null");
            return -1;
        }

        if vks.is_null() {
            set_last_error("vks is null");
            return -1;
        }

        if commitment_hr.is_null() {
            set_last_error("commitment_hr is null");
            return -1;
        }

        if commitment_vks.is_null() {
            set_last_error("commitment_vks is null");
            return -1;
        }

        if commitment_hr_len < 32 {
            set_last_error("commitment_hr_len is not at least 32");
            return -1;
        }

        if commitment_vks_len < 32 {
            set_last_error("commitment_vks_len is not at least 32");
            return -1;
        }

        if randomness_hr.is_null() {
            set_last_error("randomness_hr is null");
            return -1;
        }

        if randomness_vks.is_null() {
            set_last_error("randomness_vks is null");
            return -1;
        }

        if randomness_hr_len < 32 {
            set_last_error("randomness_hr_len is not at least 32");
            return -1;
        }

        if randomness_vks_len < 32 {
            set_last_error("randomness_vks_len is not at least 32");
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
pub extern "C" fn sender_issue_tag(sender_id: u64, as_tag: *const u8, as_tag_len: u64, randomness_hr: *const u8, randomness_hr_len: u64, randomness_vks: *const u8, randomness_vks_len: u64, vks: *const u8, vks_len: u64, sender_tag: *mut u8, sender_tag_len: u64) -> i32 {
    unsafe {
        if as_tag.is_null() {
            set_last_error("as_tag is null");
            return -1;
        }

        if randomness_hr.is_null() {
            set_last_error("randomness_hr is null");
            return -1;
        }

        if randomness_vks.is_null() {
            set_last_error("randomness_vks is null");
            return -1;
        }

        if vks.is_null() {
            set_last_error("vks is null");
            return -1;
        }

        if as_tag_len < 32 {
            set_last_error("as_tag_len is not at least 32");
            return -1;
        }

        if randomness_hr_len < 32 {
            set_last_error("randomness_hr_len is not at least 32");
            return -1;
        }

        if randomness_vks_len < 32 {
            set_last_error("randomness_vks_len is not at least 32");
            return -1;
        }

        if vks_len < 32 {
            set_last_error("vks_len is not at least 32");
            return -1;
        }

        if sender_tag.is_null() {
            set_last_error("sender_tag is null");
            return -1;
        }

        if sender_tag_len < 320 {
            set_last_error("sender_tag_len should be at least 320");
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
                let sender = match get_sender_mut_ref(sender_id) {
                    Ok(s) => s,
                    Err(e) => {
                        set_last_error(&e.0);
                        return -1;
                    }
                };

                let result = sender.get_tag_from_as_tag(
                    tag,
                    randomness_hr_slice.try_into().unwrap(),
                    randomness_vks_slice.try_into().unwrap(),
                    vks_slice,
                    &mut rng);
                match result {
                    Ok(sender_tag) => {
                        let sender_tag_buff = sender_tag.to_vec();
                        let test = SenderTag::from_slice(sender_tag_buff.as_slice());
                        assert!(test.is_ok());
                        if sender_tag_buff.len() as u64 > sender_tag_len {
                            set_last_error(&format!("sender_tag_len is too small: {}, required: {}", sender_tag_len, sender_tag_buff.len()));
                            return -1;
                        }

                        sender_tag_slice.copy_from_slice(sender_tag_buff.as_slice());
                        return 0;
                    },
                    Err(e) => {
                        set_last_error(&format!("Error issuing tag: {}", e.0));
                        return -1;
                    }
                }
            }
            Err(e) => {
                set_last_error(&format!("Error reading AS tag: {}", e.to_string()));
                return -1;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn sender_serialize(sender_id: u64, buffer: *mut u8, buffer_len: u64) -> i32 {
    unsafe {
        // When buffer is null we will return the actual size needed to serialize
        let sender = match get_sender_ref(sender_id) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&e.0);
                return -1;
            }
        };

        let sender_bytes = sender.to_bytes();
        if buffer.is_null() {
            return sender_bytes.len() as i32;
        }

        if buffer_len < sender_bytes.len().try_into().unwrap() {
            let msg = format!("buffer_len is not at least {}", sender_bytes.len());
            set_last_error(&msg);
            return -1;
        }

        let buffer_slice = std::slice::from_raw_parts_mut(buffer, sender_bytes.len());
        buffer_slice.copy_from_slice(sender_bytes.as_slice());
        return sender_bytes.len() as i32;
    }
}

#[no_mangle]
pub extern "C" fn sender_deserialize(sender_bytes: *const u8, sender_bytes_len: u64, sender_id: *mut u64) -> i32 {
    unsafe {
        if sender_bytes.is_null() {
            set_last_error("sender_bytes is null");
            return -1;
        }

        if sender_bytes_len < 1 {
            set_last_error("sender_bytes_len is less than 1");
            return -1;
        }

        if sender_id.is_null() {
            set_last_error("sender_id is null");
            return -1;
        }

        let sender_bytes_slice = std::slice::from_raw_parts(sender_bytes, sender_bytes_len.try_into().unwrap());
        let sender_result = Sender::from_slice(sender_bytes_slice);
        match sender_result {
            Ok(sender) => {
                let sdr_id = OsRng.next_u64();
                add_sender_instance(sdr_id, sender);
                *sender_id = sdr_id;
                return 0;
            },
            Err(e) => {
                set_last_error(&format!("Error deserializing sender: {}", e.0));
                return -1;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn sender_destroy_sender(sender_id: u64) {
    unsafe {
        match SENDER_INSTANCES {
            Some(ref mut senders) => {
                senders.remove(&sender_id);
            },
            None => {
                // Nothing to destroy
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    #[test]
    fn test_sender_init_sender() {
        let handle = "test";
        let sender_id: u64 = 0;
        let mut rng = OsRng;
        let sender = super::Sender::new(handle, &mut rng);
        super::add_sender_instance(sender_id, sender);
        let sender_ref = super::get_sender_ref(sender_id);
        assert!(sender_ref.is_ok());
        super::sender_destroy_sender(sender_id);
        let sender_ref = super::get_sender_ref(sender_id);
        assert!(sender_ref.is_err());
    }
}
