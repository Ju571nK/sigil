//! Named proptest arbitraries — single canonical definition per spec 5.3.
//!
//! Note: this file lives in `tests/` (separate compilation unit). Strategies
//! are kept here for documentation and future reuse via path-include.

#![allow(dead_code)]

use andeda_core::policy::{Override, Platform, Tier, WatchTarget};
use proptest::collection::vec;
use proptest::prelude::*;

pub fn arb_target() -> impl Strategy<Value = WatchTarget> {
    ("[a-z][a-z0-9-]{2,15}", any::<u8>()).prop_map(|(id, n)| WatchTarget {
        id,
        description: format!("d{n}"),
        tier: if n % 2 == 0 {
            Tier::Critical
        } else {
            Tier::Standard
        },
        platform: match n % 3 {
            0 => Platform::Macos,
            1 => Platform::Windows,
            _ => Platform::Any,
        },
        paths: vec![format!("/p{n}")],
        recursive: false,
        follow_symlinks: false,
        disabled: false,
    })
}

pub fn arb_targets() -> impl Strategy<Value = Vec<WatchTarget>> {
    vec(arb_target(), 0..20).prop_map(|mut ts| {
        for (i, t) in ts.iter_mut().enumerate() {
            t.id = format!("{}-{i}", t.id);
        }
        ts
    })
}

pub fn arb_overrides_for(targets: &[WatchTarget]) -> impl Strategy<Value = Vec<Override>> {
    if targets.is_empty() {
        return Just(Vec::new()).boxed();
    }
    let ids: Vec<String> = targets.iter().map(|t| t.id.clone()).collect();
    vec(
        (proptest::sample::select(ids), any::<bool>(), any::<bool>()).prop_map(
            |(id, dis, tier_changed)| Override {
                id,
                disabled: if dis { Some(true) } else { None },
                tier: if tier_changed {
                    Some(Tier::Standard)
                } else {
                    None
                },
            },
        ),
        0..5,
    )
    .boxed()
}
