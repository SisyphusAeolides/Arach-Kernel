use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=linker.ld");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("none") {
        return;
    }
    let script = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("linker.ld");
    println!(
        "cargo:rustc-link-arg-bin=arach-c0-probe=-T{}",
        script.display()
    );
    println!("cargo:rustc-link-arg-bin=arach-c0-probe=--no-pie");
    println!("cargo:rustc-link-arg-bin=arach-c0-probe=--no-dynamic-linker");
    println!("cargo:rustc-link-arg-bin=arach-c0-probe=--gc-sections");

    println!("cargo:rerun-if-env-changed=ARACH_EXEC_TARGET_IMAGE");
    let image = env::var_os("ARACH_EXEC_TARGET_IMAGE")
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
        .filter(|path| path.is_file())
        .unwrap_or_else(|| panic!("ARACH_EXEC_TARGET_IMAGE must name the built exec probe"));
    let length = fs::metadata(&image)
        .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", image.display()))
        .len();
    if length == 0 || length > 64 * 1024 {
        panic!("exec probe must be non-empty and at most 64 KiB, got {length}");
    }
    println!("cargo:rerun-if-changed={}", image.display());
    emit_path("ARACH_EXEC_TARGET_IMAGE_PATH", &image);
}

fn emit_path(name: &str, path: &Path) {
    let path = path
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()));
    println!("cargo:rustc-env={name}={path}");
}
