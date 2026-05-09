use andeda_core::ratelimit::{RateLimiter, REPORT_INTERVAL};
use std::path::PathBuf;

#[test]
fn rate_limiter_drops_excess_and_reports() {
    let mut r = RateLimiter::new();
    let mut dropped = 0u64;
    for i in 0..400u64 {
        if !r.allow("t1", 0) {
            r.record_drop("t1", PathBuf::from(format!("/x/{i}.json")), 0);
            dropped += 1;
        }
    }
    assert!(dropped > 0);
    let now = REPORT_INTERVAL.as_millis() as u64;
    let reports = r.drain_reports(now);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].count_dropped, dropped);
    assert!(reports[0].common_prefix.starts_with("/x"));
}
