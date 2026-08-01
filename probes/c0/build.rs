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

    let image = required_probe("ARACH_EXEC_TARGET_IMAGE", "exec probe");
    emit_path("ARACH_EXEC_TARGET_IMAGE_PATH", &image);
    let runtime_linker = required_probe("ARACH_RUNTIME_LINKER_IMAGE", "runtime linker probe");
    emit_path("ARACH_RUNTIME_LINKER_IMAGE_PATH", &runtime_linker);
}

fn required_probe(variable: &str, label: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed={variable}");
    let image = env::var_os(variable)
        .map(PathBuf::from)
        .and_then(|path| fs::canonicalize(path).ok())
        .filter(|path| path.is_file())
        .unwrap_or_else(|| panic!("{variable} must name the built {label}"));
    let length = fs::metadata(&image)
        .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", image.display()))
        .len();
    if length == 0 || length > 64 * 1024 {
        panic!("{label} must be non-empty and at most 64 KiB, got {length}");
    }
    println!("cargo:rerun-if-changed={}", image.display());
    image
}

fn emit_path(name: &str, path: &Path) {
    let path = path
        .to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()));
    println!("cargo:rustc-env={name}={path}");
}
