use std::os::raw::c_char;

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

#[no_mangle]
pub extern "C" fn get_last_error(error: *mut c_char, error_len: u64) -> i32 {
    unsafe {
        let is_empty = LAST_ERROR.with(|le| le.borrow().is_none());
        if is_empty {
            return 0;
        }

        let last_error = LAST_ERROR.with(|le| {
            le.borrow().as_ref().unwrap().clone()
        });

        if error.is_null() {
            return last_error.len() as i32;
        }

        if last_error.len() as u64 > error_len {
            return -1;
        }

        let c_str = std::ffi::CString::new(last_error.as_str()).unwrap();
        std::ptr::copy_nonoverlapping(c_str.as_ptr(), error, last_error.len());

        return last_error.len() as i32;
    }
}

pub(crate) fn set_last_error(err: &str) {
    LAST_ERROR.with(|le| {
        *le.borrow_mut() = Some(err.to_string());
    });
}
