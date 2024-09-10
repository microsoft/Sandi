use std::os::raw::c_char;

pub(crate) static mut LAST_ERROR: Option<String> = None;
static mut LAST_ERROR_PTR: *const c_char = std::ptr::null();

#[no_mangle]
pub extern "C" fn get_last_error() -> *const c_char {
    unsafe {
        if LAST_ERROR.is_none() {
            return std::ptr::null();
        }

        let err_msg = LAST_ERROR.as_ref().unwrap();
        let c_str = std::ffi::CString::new(err_msg.as_str()).unwrap();
        LAST_ERROR_PTR = c_str.as_ptr();
        LAST_ERROR_PTR
    }
}
