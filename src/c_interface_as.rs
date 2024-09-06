use curve25519_dalek::{ristretto::CompressedRistretto};
use rand::rngs::OsRng;
use crate::accountability_server::{AccServerParams, AccountabilityServer};

static mut ACC_SERVER_INSTANCE: Option<AccountabilityServer> = None;
static mut LAST_ERROR: Option<String> = None;

#[no_mangle]
pub extern "C" fn init_acc_server(epoch_start: i64, epoch_duration: i64, tag_duration: i64, max_vks_per_epoch: i64) {
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
pub extern "C" fn set_sender_epk(epk: &[u8], sender_handle: &str) -> i32 {
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
