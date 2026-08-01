use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("linker.ld");
    println!(
        "cargo:rustc-link-arg-bin=arach-exec-target=-T{}",
        script.display()
    );
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--no-pie");
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--no-dynamic-linker");
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--gc-sections");
}
