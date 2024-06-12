use std::env;

fn main() {
    if env::var("TARGET_NANOS").is_ok() {
        println!("cargo:rustc-cfg=target_nanos");
    }
}
