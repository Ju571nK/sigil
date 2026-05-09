use andeda_core::ratelimit::{RateLimiter, REPORT_INTERVAL};
use std::path::PathBuf;

#[test]
fn it_emits_channel_stall_via_rate_limit_drop() {
    // Phase 1 reports backpressure-equivalent loss via RateLimiter (per spec 1.8 + 4.2).
    let mut r = RateLimiter::new();
    for i in 0..1000u64 {
        if !r.allow("t", 0) {
            r.record_drop("t", PathBuf::from(format!("/spam/{i}")), 0);
        }
    }
    let reports = r.drain_reports(REPORT_INTERVAL.as_millis() as u64);
    assert_eq!(reports.len(), 1);
    assert!(reports[0].count_dropped > 700);
}
