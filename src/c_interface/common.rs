use std::os::raw::c_char;

pub(crate) static mut LAST_ERROR: Option<String> = None;

#[no_mangle]
pub extern "C" fn get_last_error(error: *mut c_char, error_len: u64) -> i32 {
    unsafe {
        if LAST_ERROR.is_none() {
            return 0;
        }

        let last_error = unsafe { LAST_ERROR.as_ref().unwrap() };
        if error.is_null() {
            return last_error.len() as i32;
        }

        if last_error.len() as u64 > error_len {
            return -1;
        }

        let c_str = std::ffi::CString::new(last_error.as_str()).unwrap();
        unsafe {
            std::ptr::copy_nonoverlapping(c_str.as_ptr(), error, last_error.len());
        }

        return last_error.len() as i32;
    }
}
