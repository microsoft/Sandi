use std::{collections::HashMap, os::raw::c_char, os::raw::c_double, convert::TryInto};

use curve25519_dalek::ristretto::CompressedRistretto;
use rand::{rngs::OsRng, RngCore};
use acctblty::{accountability_server::{AccServerParams, AccountabilityServer}, sender_tag::SenderTag};
use super::common::set_last_error;

static mut ACC_SERVER_INSTANCES: Option<HashMap<u64, AccountabilityServer>> = None;

struct AccServerInstError(pub String);

fn get_acc_server_mut_ref(acc_server_id: u64) -> Result<&'static mut AccountabilityServer, AccServerInstError> {
    unsafe {
        match ACC_SERVER_INSTANCES {
            Some(ref mut instances) => {
                match instances.get_mut(&acc_server_id) {
                    Some(acc_server) => Ok(acc_server),
                    None => Err(AccServerInstError(format!("Accountability server instance {} not found", acc_server_id)))
                }
            }
            None => Err(AccServerInstError("Accountability server instances is not initialized".to_string()))
        }
    }
}

fn get_acc_server_ref(acc_server_id: u64) -> Result<&'static AccountabilityServer, AccServerInstError> {
    unsafe {
        match ACC_SERVER_INSTANCES {
            Some(ref instances) => {
                match instances.get(&acc_server_id) {
                    Some(acc_server) => Ok(acc_server),
                    None => Err(AccServerInstError(format!("Accountability server instance {} not found", acc_server_id)))
                }
            }
            None => Err(AccServerInstError("Accountability server instances is not initialized".to_string()))
        }
    }
}

fn add_acc_server_instance(acc_server_id: u64, acc_server: AccountabilityServer) {
    unsafe {
        match ACC_SERVER_INSTANCES {
            Some(ref mut instances) => {
                instances.insert(acc_server_id, acc_server);
            },
            None => {
                let mut instances = HashMap::new();
                instances.insert(acc_server_id, acc_server);
                ACC_SERVER_INSTANCES = Some(instances);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn as_init_acc_server(epoch_start: i64, epoch_duration: i64, tag_duration: i64, max_vks_per_epoch: i64) -> u64 {
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

    let mut rng = OsRng;
    let acc_server = AccountabilityServer::new(params, &mut rng);
    let acc_server_id = rng.next_u64();
    add_acc_server_instance(acc_server_id, acc_server);
    return acc_server_id;
}

#[no_mangle]
pub extern "C" fn as_get_verifying_key(acc_server_id: u64, verif_key: *mut u8, verif_key_len: u64) -> i32 {
    if verif_key.is_null() {
        set_last_error("verif_key is null");
        return -1;
    }

    if verif_key_len < 32 {
        set_last_error("verif_key_len should be at least 32");
        return -1;
    }

    let acc_server = get_acc_server_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let verifying_key = acc_server.get_verifying_key();
            let verif_key_slice = unsafe { std::slice::from_raw_parts_mut(verif_key, verif_key_len.try_into().unwrap()) };
            verif_key_slice.copy_from_slice(&verifying_key);
            return 0;
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_set_sender_epk(acc_server_id: u64, epk: *const u8, epk_len: u64, sender_handle: *const c_char) -> i32 {
    if epk.is_null() {
        set_last_error("epk is null");
        return -1;
    }

    if sender_handle.is_null() {
        set_last_error("sender_handle is null");
        return -1;
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };
    let epk = unsafe { std::slice::from_raw_parts(epk, epk_len.try_into().unwrap()) };

    let acc_server = get_acc_server_mut_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let epk_res = CompressedRistretto::from_slice(epk).unwrap().decompress().ok_or("Failed to decompress epk");
            match epk_res {
                Ok(epk) => match acc_server.set_sender_epk(&epk, sender_handle) {
                    Ok(_) => {
                        return 0;
                    },
                    Err(err_msg) => {
                        set_last_error(&err_msg.0);
                        return -1;
                    }
                },
                Err(err_msg) => {
                    set_last_error(err_msg);
                    return -1;
                }
            }
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_get_sender_epk(acc_server_id: u64, sender_handle: *const c_char, epk: *mut u8, epk_len: u64) -> i32 {
    if sender_handle.is_null() {
        set_last_error("sender_handle is null");
        return -1;
    }

    if epk.is_null() {
        set_last_error("epk is null");
        return -1;
    }

    if epk_len < 32 {
        set_last_error("epk_len should be at least 32");
        return -1;
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };
    let epk_result = unsafe { std::slice::from_raw_parts_mut(epk, epk_len.try_into().unwrap()) };

    let acc_server = get_acc_server_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let epk = acc_server.get_sender_epk(sender_handle);
            match epk {
                Ok(epk) => {
                    let epk_slice = epk.compress().to_bytes();
                    epk_result.copy_from_slice(&epk_slice);
                    return 0;
                },
                Err(err) => {
                    set_last_error(format!("Sender not found: {}", err.0).as_str());
                    return -1;
                }
            }
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_get_sender_score(acc_server_id: u64, sender_handle: *const c_char, sender_score: *mut c_double) -> i32 {
    if sender_handle.is_null() {
        set_last_error("sender_handle is null");
        return -1;
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };

    let acc_server = get_acc_server_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let score = acc_server.get_sender_score(sender_handle);
            match score {
                Ok(score) => {
                    unsafe { *sender_score = score };
                    return 0;
                },
                Err(err_msg) => {
                    set_last_error(&err_msg.0);
                    return -1;
                }
            }
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_issue_tag(acc_server_id: u64, sender_handle: *const c_char, commitment_hr: *const u8, commitment_hr_len: u64, commitment_vks: *const u8, commitment_vks_len: u64, tag: *mut u8, tag_len: u64) -> i32 {
    if sender_handle.is_null() {
        set_last_error("sender_handle is null");
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

    if commitment_hr_len != 32 {
        set_last_error("commitment_hr_len is not 32");
        return -1;
    }

    if commitment_vks_len != 32 {
        set_last_error("commitment_vks_len is not 32");
        return -1;
    }

    if tag.is_null() {
        set_last_error("tag is null");
        return -1;
    }

    if tag_len < 320 {
        set_last_error("tag_len should be at least 320");
        return -1;
    }

    let sender_handle = unsafe { std::ffi::CStr::from_ptr(sender_handle).to_str().unwrap() };
    let commitment_hr = unsafe { std::slice::from_raw_parts(commitment_hr, commitment_hr_len.try_into().unwrap()) };
    let commitment_vks = unsafe { std::slice::from_raw_parts(commitment_vks, commitment_vks_len.try_into().unwrap()) };
    let tag_result = unsafe { std::slice::from_raw_parts_mut(tag, tag_len.try_into().unwrap()) };

    //let acc_server = unsafe { ACC_SERVER_INSTANCE.as_mut().unwrap() };
    let acc_server = get_acc_server_mut_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let issue_result = acc_server.issue_tag(commitment_hr, commitment_vks, sender_handle, &mut OsRng);
            match issue_result {
                Ok(tag) => {
                    let tag_vec = tag.to_vec();
                    if (tag_vec.len() as u64) > tag_len {
                        let msg = format!("tag_len is too small: {}, required: {}", tag_len, tag_vec.len());
                        set_last_error(&msg);
                        return -1;
                    }
                    tag_result.copy_from_slice(&tag_vec.as_slice());
                    return 0;
                },
                Err(err_msg) => {
                    set_last_error(&err_msg.0);
                    return -1;
                }
            }
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_report_tag(acc_server_id: u64, tag: *const u8, tag_len: u64) -> i32 {
    unsafe {
        if tag.is_null() {
            set_last_error("tag is null");
            return -1;
        }

        let tag_buff = std::slice::from_raw_parts(tag, tag_len.try_into().unwrap());

        //let acc_server = ACC_SERVER_INSTANCE.as_mut().unwrap();
        let acc_server = get_acc_server_mut_ref(acc_server_id);
        match acc_server {
            Ok(acc_server) => {
                let sender_tag = SenderTag::from_slice(tag_buff);
                match sender_tag {
                    Ok(sender_tag) => {
                        let report_result = acc_server.report(&sender_tag.report_tag);
                        match report_result {
                            Ok(_) => return 0,
                            Err(err_msg) => {
                                set_last_error(&err_msg.0);
                                return -1;
                            }
                        }
                    },
                    Err(err_msg) => {
                        set_last_error(&err_msg);
                        return -1;
                    }
                }
            },
            Err(err_msg) => {
                set_last_error(&err_msg.0);
                return -1;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn as_update_scores(acc_server_id: u64) -> i32 {
    let acc_server = get_acc_server_mut_ref(acc_server_id);
    match acc_server {
        Ok(acc_server) => {
            let mut rng = OsRng;
            acc_server.update_scores(&mut rng);
            return 0;
        },
        Err(err_msg) => {
            set_last_error(&err_msg.0);
            return -1;
        }
    }
}

#[no_mangle]
pub extern "C" fn as_destroy_acc_server(acc_server_id: u64) {
    unsafe {
        match ACC_SERVER_INSTANCES {
            Some(ref mut instances) => {
                instances.remove(&acc_server_id);
            },
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_as_init_acc_server() {
        let acc_server_id = super::as_init_acc_server(0, 60, 10, 10);
        assert!(acc_server_id > 0);
        super::as_destroy_acc_server(acc_server_id);
    }

    #[test]
    fn test_get_acc_server() {
        let acc_server_id = super::as_init_acc_server(0, 60, 10, 10);
        let acc_server = super::get_acc_server_ref(acc_server_id);
        assert!(acc_server.is_ok());
        super::as_destroy_acc_server(acc_server_id);
        let acc_server = super::get_acc_server_ref(acc_server_id);
        assert!(acc_server.is_err());
    }
}