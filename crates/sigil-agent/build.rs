// Phase 3c — doctor --verify-self 가 자기 target triple 을 알도록 빌드타임에 캡처.
fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=SIGIL_BUILD_TARGET={target}");
}
