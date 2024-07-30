use chrono::{DateTime, NaiveDateTime, Utc};


pub fn get_start_of_day(timestamp: i64) -> i64 {
    // Get UTC DateTimne frin timestamp
    let dt = DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap(), Utc);

    // Get start of day
    let date_part = dt.naive_utc();
    let start_of_day = date_part.date().and_hms_opt(0, 0, 0).unwrap().and_utc();
    start_of_day.timestamp()
}

pub fn get_epoch(timestamp: i64, epoch_duration: i64, epoch_start: i64) -> i64 {
    // epoch_duration is in hours. Needs to be a multiple of 24.
    assert_eq!(epoch_duration % 24, 0);

    // Get the elapsed number of hours since the epoch start
    let elapsed_hours = (timestamp - epoch_start) / 3600;
    let epoch = elapsed_hours / epoch_duration;
    epoch
}

pub fn get_lock_timestamp(time_stamp: i64, lock_duration: i64, epoch_duration: i64) -> i64 {
    // epoch_duration is in hours. Needs to be a multiple of 24.
    assert_eq!(epoch_duration % 24, 0);

    // lock duration is in epochs
    let elapsed_hours = epoch_duration * lock_duration;

    let lock_timestamp = time_stamp + elapsed_hours * 3600;
    lock_timestamp
}

pub fn get_timestamp_for_date_and_time(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> i64 {
    let dt = NaiveDateTime::new(
        chrono::NaiveDate::from_ymd_opt(year, month, day).unwrap(),
        chrono::NaiveTime::from_hms_opt(hour, minute, second).unwrap(),
    );
    dt.timestamp()
}

pub fn get_timestamp_for_date(year: i32, month: u32, day: u32) -> i64 {
    get_timestamp_for_date_and_time(year, month, day, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use chrono::{Datelike, Timelike};
    use super::*;

    fn get_date_from_timestamp(timestamp: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_naive_utc_and_offset(NaiveDateTime::from_timestamp_opt(timestamp, 0).unwrap(), Utc)
    }
    
    #[test]
    fn test_get_start_of_day() {
        let timestamp = 1614616260; // 2021-03-01 16:31:00 UTC
        let date = get_date_from_timestamp(timestamp);
        assert_eq!(date.year(), 2021);
        assert_eq!(date.month(), 3);
        assert_eq!(date.day(), 1);
        assert_eq!(date.hour(), 16);
        assert_eq!(date.minute(), 31);
        assert_eq!(date.second(), 0);

        let start_of_day = get_start_of_day(timestamp);
        let date2 = get_date_from_timestamp(start_of_day);
        assert_eq!(date2.year(), 2021);
        assert_eq!(date2.month(), 3);
        assert_eq!(date2.day(), 1);
        assert_eq!(date2.hour(), 0);
        assert_eq!(date2.minute(), 0);
        assert_eq!(date2.second(), 0);
    }

    #[test]
    fn test_get_epoch() {
        let timestamp = 1617160676; // 2021-03-31 03:17:56 UTC
        let date = get_date_from_timestamp(timestamp);
        assert_eq!(date.year(), 2021);
        assert_eq!(date.month(), 3);
        assert_eq!(date.day(), 31);
        assert_eq!(date.hour(), 3);
        assert_eq!(date.minute(), 17);
        assert_eq!(date.second(), 56);

        let epoch_duration = 48;
        let epoch_start_timestamp = 1614556800; // 2021-03-01 00:00:00 UTC

        let epoch = get_epoch(timestamp, epoch_duration, epoch_start_timestamp);
        assert_eq!(epoch, 15);

        let epoch_duration = 72;
        let epoch = get_epoch(timestamp, epoch_duration, epoch_start_timestamp);
        assert_eq!(epoch, 10);
    }

    #[test]
    fn test_get_timestamp_for_date_and_time() {
        let timestamp = get_timestamp_for_date_and_time(2021, 3, 31, 3, 17, 56);
        let date = get_date_from_timestamp(timestamp);
        assert_eq!(date.year(), 2021);
        assert_eq!(date.month(), 3);
        assert_eq!(date.day(), 31);
        assert_eq!(date.hour(), 3);
        assert_eq!(date.minute(), 17);
        assert_eq!(date.second(), 56);
    }

    #[test]
    fn test_get_lock_timestamp() {
        let timestamp = 1617160676; // 2021-03-31 03:17:56 UTC
        let epoch_duration = 48;
        let lock_timestamp = get_lock_timestamp(timestamp, 2, epoch_duration);
        let date = get_date_from_timestamp(lock_timestamp);
        assert_eq!(date.year(), 2021);
        assert_eq!(date.month(), 4);
        assert_eq!(date.day(), 4); // 4 days
        assert_eq!(date.hour(), 3);
        assert_eq!(date.minute(), 17);
        assert_eq!(date.second(), 56);
    }
}
