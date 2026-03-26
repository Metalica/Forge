fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").ok();
    if target_os.as_deref() == Some("windows") {
        println!("cargo:rustc-link-lib=dylib=advapi32");
        let target_env = std::env::var("CARGO_CFG_TARGET_ENV").ok();
        if target_env.as_deref() == Some("gnu") {
            println!("cargo:rustc-link-arg=-ladvapi32");
        }
    }
}
