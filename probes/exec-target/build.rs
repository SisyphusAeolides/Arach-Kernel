use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("linker.ld");
    let shared_object = PathBuf::from(
        env::var_os("ARACH_SHARED_OBJECT_IMAGE")
            .expect("ARACH_SHARED_OBJECT_IMAGE must name the measured root object"),
    );
    let shared_directory = shared_object
        .parent()
        .expect("the measured root object must have a parent directory");
    let shared_metadata = fs::symlink_metadata(&shared_object)
        .expect("the measured root object must be readable");
    assert!(shared_metadata.file_type().is_file());
    assert_eq!(
        shared_object.file_name().and_then(|name| name.to_str()),
        Some("libarach-probe.so")
    );
    println!("cargo:rerun-if-env-changed=ARACH_SHARED_OBJECT_IMAGE");
    println!("cargo:rerun-if-changed={}", shared_object.display());
    println!(
        "cargo:rustc-link-arg-bin=arach-exec-target=-T{}",
        script.display()
    );
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--pie");
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--gc-sections");
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--hash-style=sysv");
    println!(
        "cargo:rustc-link-arg-bin=arach-exec-target=-L{}",
        shared_directory.display()
    );
    println!("cargo:rustc-link-arg-bin=arach-exec-target=--no-as-needed");
    println!("cargo:rustc-link-arg-bin=arach-exec-target=-l:libarach-probe.so");
}
