use sigil_core::policy::expand::{expand_per_user, UserContext, VarLookup};
use std::path::PathBuf;

struct EmptyVars;
impl VarLookup for EmptyVars {
    fn lookup(&self, _: &str) -> Option<String> {
        None
    }
    fn home(&self) -> Option<PathBuf> {
        None
    }
}

#[test]
fn it_multi_user_path_expansion() {
    let users = vec![
        UserContext {
            name: "alice".into(),
            home: PathBuf::from("/Users/alice"),
            uid_or_sid: "501".into(),
        },
        UserContext {
            name: "bob".into(),
            home: PathBuf::from("/Users/bob"),
            uid_or_sid: "502".into(),
        },
    ];
    let out = expand_per_user(
        "~/Library/Application Support/Claude/claude_desktop_config.json",
        &users,
        &EmptyVars,
    );
    assert_eq!(out.len(), 2);
    let p1 = out[0].as_ref().unwrap();
    let p2 = out[1].as_ref().unwrap();
    assert!(p1.starts_with("/Users/alice"));
    assert!(p2.starts_with("/Users/bob"));
}
