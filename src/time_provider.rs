
// Provides ability to manipulate time for testing purposes
pub(crate) trait TimeProvider {
    fn get_current_time(&self) -> i64;
}

// The default implementation will return the correct time
pub(crate) struct DefaultTimeProvider {}


impl TimeProvider for DefaultTimeProvider {
    fn get_current_time(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

