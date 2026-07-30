use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(command: &mut Command, description: &str) {
    let status = command.status().unwrap_or_else(|error| {
        panic!("failed to start {description}: {error}");
    });
    assert!(status.success(), "{description} exited with {status}");
}

fn main() {
    let manifest_directory = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    let workspace = manifest_directory.clone();
    let driver_lifecycle = workspace.join("formal/idris2/DriverLifecycle.idr");
    let package_transaction = workspace.join("formal/idris2/PackageTransaction.idr");
    let crucible = workspace.join("formal/idris2/Crucible.idr");
    let aegis_lifecycle = workspace.join("formal/idris2/AegisLifecycle.idr");
    let argus_markup = workspace.join("formal/idris2/ArgusMarkup.idr");
    let granite_boot = workspace.join("formal/idris2/GraniteBoot.idr");
    let hermes_authority = workspace.join("formal/idris2/HermesAuthority.idr");
    let crest_shell = workspace.join("formal/idris2/CrestShell.idr");
    let privilege_rings = workspace.join("formal/agda/PrivilegeRings.agda");
    let argus_layout = workspace.join("formal/agda/ArgusLayout.agda");
    let granite_layout = workspace.join("formal/agda/GraniteLayout.agda");
    let hermes_wire = workspace.join("formal/agda/HermesWire.agda");
    let crest_overlay = workspace.join("formal/agda/CrestOverlay.agda");
    let cosmic_compatibility = workspace.join("formal/idris2/CosmicCompatibility.idr");
    let cosmic_stack = workspace.join("formal/agda/CosmicStack.agda");
    let linux_contract_idris = workspace.join("formal/idris2/LinuxContract.idr");
    let linux_contract_agda = workspace.join("formal/agda/LinuxContract.agda");
    let driver_digest = measured_source(&driver_lifecycle);
    let package_digest = measured_source(&package_transaction);
    let crucible_digest = measured_source(&crucible);
    let aegis_digest = measured_source(&aegis_lifecycle);
    let argus_markup_digest = measured_source(&argus_markup);
    let granite_boot_digest = measured_source(&granite_boot);
    let hermes_authority_digest = measured_source(&hermes_authority);
    let crest_shell_digest = measured_source(&crest_shell);
    let privilege_digest = measured_source(&privilege_rings);
    let argus_layout_digest = measured_source(&argus_layout);
    let granite_layout_digest = measured_source(&granite_layout);
    let hermes_wire_digest = measured_source(&hermes_wire);
    let crest_overlay_digest = measured_source(&crest_overlay);
    let cosmic_compatibility_digest = measured_source(&cosmic_compatibility);
    let cosmic_stack_digest = measured_source(&cosmic_stack);
    let linux_contract_idris_digest = measured_source(&linux_contract_idris);
    let linux_contract_agda_digest = measured_source(&linux_contract_agda);
    println!("cargo:rerun-if-changed={}", driver_lifecycle.display());
    println!("cargo:rerun-if-changed={}", package_transaction.display());
    println!("cargo:rerun-if-changed={}", crucible.display());
    println!("cargo:rerun-if-changed={}", aegis_lifecycle.display());
    println!("cargo:rerun-if-changed={}", argus_markup.display());
    println!("cargo:rerun-if-changed={}", granite_boot.display());
    println!("cargo:rerun-if-changed={}", hermes_authority.display());
    println!("cargo:rerun-if-changed={}", crest_shell.display());
    println!("cargo:rerun-if-changed={}", privilege_rings.display());
    println!("cargo:rerun-if-changed={}", argus_layout.display());
    println!("cargo:rerun-if-changed={}", granite_layout.display());
    println!("cargo:rerun-if-changed={}", hermes_wire.display());
    println!("cargo:rerun-if-changed={}", crest_overlay.display());
    println!("cargo:rerun-if-changed={}", cosmic_compatibility.display());
    println!("cargo:rerun-if-changed={}", cosmic_stack.display());
    println!("cargo:rerun-if-changed={}", linux_contract_idris.display());
    println!("cargo:rerun-if-changed={}", linux_contract_agda.display());
    println!(
        "cargo:rustc-env=SISYPHUS_DRIVER_PROOF_SHA256={}",
        encode_sha256(driver_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_PACKAGE_PROOF_SHA256={}",
        encode_sha256(package_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_CRUCIBLE_PROOF_SHA256={}",
        encode_sha256(crucible_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_AEGIS_PROOF_SHA256={}",
        encode_sha256(aegis_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_ARGUS_MARKUP_PROOF_SHA256={}",
        encode_sha256(argus_markup_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_GRANITE_BOOT_PROOF_SHA256={}",
        encode_sha256(granite_boot_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_HERMES_AUTHORITY_PROOF_SHA256={}",
        encode_sha256(hermes_authority_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_CREST_SHELL_PROOF_SHA256={}",
        encode_sha256(crest_shell_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_PRIVILEGE_PROOF_SHA256={}",
        encode_sha256(privilege_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_ARGUS_LAYOUT_PROOF_SHA256={}",
        encode_sha256(argus_layout_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_GRANITE_LAYOUT_PROOF_SHA256={}",
        encode_sha256(granite_layout_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_HERMES_WIRE_PROOF_SHA256={}",
        encode_sha256(hermes_wire_digest)
    );
    println!(
        "cargo:rustc-env=SISYPHUS_CREST_OVERLAY_PROOF_SHA256={}",
        encode_sha256(crest_overlay_digest)
    );
    println!(
        "cargo:rustc-env=ARACH_COSMIC_COMPATIBILITY_PROOF_SHA256={}",
        encode_sha256(cosmic_compatibility_digest)
    );
    println!(
        "cargo:rustc-env=ARACH_COSMIC_STACK_PROOF_SHA256={}",
        encode_sha256(cosmic_stack_digest)
    );
    println!(
        "cargo:rustc-env=ARACH_LINUX_CONTRACT_IDRIS_SHA256={}",
        encode_sha256(linux_contract_idris_digest)
    );
    println!(
        "cargo:rustc-env=ARACH_LINUX_CONTRACT_AGDA_SHA256={}",
        encode_sha256(linux_contract_agda_digest)
    );

    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=src/bootstrap.S");
    println!("cargo:rerun-if-changed=src/interrupts/stubs.S");
    println!("cargo:rerun-if-changed=include/sisyphus/driver.h");
    println!("cargo:rerun-if-changed=include/sisyphus/gpu.h");
    println!("cargo:rerun-if-changed=drivers/reference/reference_driver.c");
    println!("cargo:rerun-if-changed=fortran/arach_control.f90");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=FC");
    println!("cargo:rerun-if-env-changed=AR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        verify_formal_attestation(
            &workspace,
            driver_digest,
            package_digest,
            crucible_digest,
            aegis_digest,
            argus_markup_digest,
            granite_boot_digest,
            hermes_authority_digest,
            crest_shell_digest,
            privilege_digest,
            argus_layout_digest,
            granite_layout_digest,
            hermes_wire_digest,
            crest_overlay_digest,
            cosmic_compatibility_digest,
            cosmic_stack_digest,
            linux_contract_idris_digest,
            linux_contract_agda_digest,
        );
        let linker_script = PathBuf::from(
            env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
        )
        .join("linker.ld");
        println!(
            "cargo:rustc-link-arg-bin=arach=-T{}",
            linker_script.display()
        );
        println!("cargo:rustc-link-arg-bin=arach=--gc-sections");

        println!("cargo:rerun-if-env-changed=ARACH_PUSH_IMAGE");
        let push_image = configured_file(
            "ARACH_PUSH_IMAGE",
            &workspace.join("target/x86_64-sisyphus-user/release/push"),
        );
        println!("cargo:rerun-if-changed={}", push_image.display());
        let bytes = fs::read(&push_image).unwrap_or_else(|error| {
            panic!(
                "failed to read {}: {error}; set ARACH_PUSH_IMAGE to the measured Push ELF",
                push_image.display()
            )
        });
        assert!(
            !bytes.is_empty() && bytes.len() <= 1024 * 1024,
            "Push image must be between 1 byte and 1 MiB"
        );
        let entry_file_offset = elf_entry_file_offset(&bytes);
        let digest = sha256(&bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        println!("cargo:rustc-env=SISYPHUS_PUSH_SHA256={encoded}");
        println!("cargo:rustc-env=SISYPHUS_PUSH_BYTES={}", bytes.len());
        println!("cargo:rustc-env=SISYPHUS_PUSH_ENTRY_FILE_OFFSET={entry_file_offset}");

        let bootstrap_package = selected_bootstrap_package(&workspace);
        let crest_bytes = bootstrap_package.bytes;
        assert!(
            !crest_bytes.is_empty() && crest_bytes.len() <= 1024 * 1024,
            "bootstrap image must be between 1 byte and 1 MiB"
        );
        let crest_entry_file_offset = elf_entry_file_offset(&crest_bytes);
        let crest_digest = sha256(&crest_bytes);
        let mut crest_encoded = String::with_capacity(64);
        for byte in crest_digest {
            use std::fmt::Write as _;
            write!(crest_encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        println!("cargo:rustc-env=SISYPHUS_CREST_SHA256={crest_encoded}");
        println!("cargo:rustc-env=SISYPHUS_CREST_BYTES={}", crest_bytes.len());
        println!("cargo:rustc-env=SISYPHUS_CREST_ENTRY_FILE_OFFSET={crest_entry_file_offset}");
        println!(
            "cargo:rustc-env=SISYPHUS_CREST_PACKAGE_VERSION={}",
            bootstrap_package.version_index
        );
        println!(
            "cargo:rustc-env=SISYPHUS_CREST_SERVICE_CLASS={}",
            bootstrap_package.service_class
        );
        println!(
            "cargo:rustc-env=SISYPHUS_CREST_PROVENANCE_ROOT={}",
            bootstrap_package.provenance_root
        );
    }

    let build_reference_driver = env::var_os("CARGO_FEATURE_REFERENCE_DRIVER").is_some();
    let build_fortran_control = env::var_os("CARGO_FEATURE_FORTRAN_CONTROL").is_some();
    if !build_reference_driver && !build_fortran_control {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let ar = env::var_os("AR").unwrap_or_else(|| "ar".into());

    if build_reference_driver {
        let object = out_dir.join("reference_driver.o");
        let archive = out_dir.join("libreference_driver.a");
        let cc = env::var_os("CC").unwrap_or_else(|| "cc".into());
        let mut compile_driver = Command::new(cc);
        compile_driver
            .arg("-std=c11")
            .arg("-ffreestanding")
            .arg("-fno-stack-protector")
            .arg("-fvisibility=hidden")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror");
        add_position_flags(&mut compile_driver);
        compile_driver
            .arg("-I")
            .arg(Path::new("include"))
            .arg("-c")
            .arg("drivers/reference/reference_driver.c")
            .arg("-o")
            .arg(&object);
        run(&mut compile_driver, "C reference-driver compilation");

        run(
            Command::new(&ar).arg("crs").arg(&archive).arg(&object),
            "C reference-driver archive creation",
        );

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=reference_driver");
    }

    if build_fortran_control {
        let object = out_dir.join("arach_control.o");
        let archive = out_dir.join("libarach_fortran.a");
        let fc = env::var_os("FC").unwrap_or_else(|| "gfortran".into());
        let mut compile_fortran = Command::new(fc);
        compile_fortran
            .arg("-c")
            .arg("-O2")
            .arg("-J")
            .arg(&out_dir)
            .arg("-fno-stack-protector")
            .arg("-fno-asynchronous-unwind-tables")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror");
        add_position_flags(&mut compile_fortran);
        compile_fortran
            .arg("fortran/arach_control.f90")
            .arg("-o")
            .arg(&object);
        run(&mut compile_fortran, "Fortran control-kernel compilation");

        run(
            Command::new(ar).arg("crs").arg(&archive).arg(&object),
            "Fortran control-kernel archive creation",
        );

        println!("cargo:rustc-link-search=native={}", out_dir.display());
        println!("cargo:rustc-link-lib=static=arach_fortran");
    }
}

fn add_position_flags(command: &mut Command) {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        command
            .arg("-fno-pic")
            .arg("-fno-pie")
            .arg("-mno-red-zone")
            .arg("-mcmodel=kernel");
    } else {
        command.arg("-fPIC");
    }
}

fn measured_source(path: &Path) -> [u8; 32] {
    let bytes = fs::read(path)
        .unwrap_or_else(|error| panic!("failed to read formal source {}: {error}", path.display()));
    assert!(
        !bytes.is_empty(),
        "formal source {} is empty",
        path.display()
    );
    sha256(&bytes)
}

fn encode_sha256(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn verify_formal_attestation(
    workspace: &Path,
    driver_digest: [u8; 32],
    package_digest: [u8; 32],
    crucible_digest: [u8; 32],
    aegis_digest: [u8; 32],
    argus_markup_digest: [u8; 32],
    granite_boot_digest: [u8; 32],
    hermes_authority_digest: [u8; 32],
    crest_shell_digest: [u8; 32],
    privilege_digest: [u8; 32],
    argus_layout_digest: [u8; 32],
    granite_layout_digest: [u8; 32],
    hermes_wire_digest: [u8; 32],
    crest_overlay_digest: [u8; 32],
    cosmic_compatibility_digest: [u8; 32],
    cosmic_stack_digest: [u8; 32],
    linux_contract_idris_digest: [u8; 32],
    linux_contract_agda_digest: [u8; 32],
) {
    let path = workspace.join("target/formal/verified.lock");
    println!("cargo:rerun-if-changed={}", path.display());
    let actual = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "failed to read {}: {error}; run scripts/check-formal-models.sh before cargo kernel",
            path.display()
        )
    });
    let expected = format!(
        "format=1\nidris2_version=0.8.0\nagda_version=2.8.0\n\
driver_lifecycle_sha256={}\npackage_transaction_sha256={}\n\
crucible_sha256={}\naegis_lifecycle_sha256={}\nargus_markup_sha256={}\ngranite_boot_sha256={}\n\
hermes_authority_sha256={}\ncrest_shell_sha256={}\nprivilege_rings_sha256={}\nargus_layout_sha256={}\n\
granite_layout_sha256={}\nhermes_wire_sha256={}\ncrest_overlay_sha256={}\n\
cosmic_compatibility_sha256={}\ncosmic_stack_sha256={}\n\
linux_contract_idris_sha256={}\nlinux_contract_agda_sha256={}\n",
        encode_sha256(driver_digest),
        encode_sha256(package_digest),
        encode_sha256(crucible_digest),
        encode_sha256(aegis_digest),
        encode_sha256(argus_markup_digest),
        encode_sha256(granite_boot_digest),
        encode_sha256(hermes_authority_digest),
        encode_sha256(crest_shell_digest),
        encode_sha256(privilege_digest),
        encode_sha256(argus_layout_digest),
        encode_sha256(granite_layout_digest),
        encode_sha256(hermes_wire_digest),
        encode_sha256(crest_overlay_digest),
        encode_sha256(cosmic_compatibility_digest),
        encode_sha256(cosmic_stack_digest),
        encode_sha256(linux_contract_idris_digest),
        encode_sha256(linux_contract_agda_digest),
    );
    assert_eq!(
        actual, expected,
        "formal attestation is stale or contradictory; rerun scripts/check-formal-models.sh"
    );
}

struct BootProcessPackage {
    bytes: Vec<u8>,
    version_index: u16,
    service_class: u16,
    provenance_root: u64,
}

fn selected_bootstrap_package(workspace: &Path) -> BootProcessPackage {
    println!("cargo:rerun-if-env-changed=ARACH_BOOTSTRAP_IMAGE");
    if let Some(candidate) = env::var_os("ARACH_BOOTSTRAP_IMAGE") {
        let artifact = fs::canonicalize(PathBuf::from(candidate)).unwrap_or_else(|error| {
            panic!("failed to resolve ARACH_BOOTSTRAP_IMAGE: {error}");
        });
        assert!(
            artifact.is_file(),
            "ARACH_BOOTSTRAP_IMAGE must name a regular file"
        );
        println!("cargo:rerun-if-changed={}", artifact.display());
        let bytes = fs::read(&artifact)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", artifact.display()));
        return BootProcessPackage {
            provenance_root: provenance_root(&[sha256(&bytes)]),
            bytes,
            version_index: 1,
            service_class: 2,
        };
    }
    println!("cargo:rerun-if-env-changed=SISYPHUS_CREST_PACKAGE");
    let Some(candidate) = env::var_os("SISYPHUS_CREST_PACKAGE") else {
        let image = workspace.join("target/x86_64-sisyphus-user/release/crest");
        println!("cargo:rerun-if-changed={}", image.display());
        let bytes = fs::read(&image).unwrap_or_else(|error| {
            panic!(
                "failed to read {}: {error}; run `cargo user-crest` before building Arach",
                image.display()
            )
        });
        let cargo_lock = workspace.join("Cargo.lock");
        let toolchain = workspace.join("rust-toolchain.toml");
        println!("cargo:rerun-if-changed={}", cargo_lock.display());
        println!("cargo:rerun-if-changed={}", toolchain.display());
        return BootProcessPackage {
            bytes,
            version_index: 3,
            service_class: 2,
            provenance_root: provenance_root(&[
                measured_source(&cargo_lock),
                measured_source(&toolchain),
            ]),
        };
    };

    let root = fs::canonicalize(PathBuf::from(candidate)).unwrap_or_else(|error| {
        panic!("failed to resolve SISYPHUS_CREST_PACKAGE: {error}");
    });
    assert!(
        root.is_dir(),
        "SISYPHUS_CREST_PACKAGE must name a directory"
    );
    let manifest = rooted_file(&root, "package.toml");
    let manifest_text = fs::read_to_string(&manifest).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", manifest.display());
    });
    let record = CandidateRecord::parse(&manifest_text);
    assert_eq!(record.schema_version, 1, "unsupported candidate schema");
    assert_eq!(
        record.source, "crates.io",
        "candidate source must be crates.io"
    );
    assert!(
        valid_atom(record.crate_name),
        "invalid candidate crate name"
    );
    assert!(!record.version.is_empty(), "candidate version is empty");
    assert!(valid_atom(record.binary), "invalid candidate binary name");
    assert_eq!(
        record.service_class, 2,
        "only Crest's service class is boot-admitted"
    );
    assert!(
        record.package_version_index != 0,
        "candidate package version is zero"
    );
    assert_eq!(
        record.target, "x86_64-sisyphus-user",
        "candidate target mismatch"
    );
    assert_eq!(
        record.artifact,
        format!("root/bin/{}", record.binary),
        "candidate artifact path does not match its binary identity"
    );

    let artifact = rooted_file(&root, record.artifact);
    let resolution_lock = rooted_file(&root, "source-request/Cargo.lock");
    let source_lock = rooted_file(&root, "source-package.Cargo.lock");
    let bytes = fs::read(&artifact)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", artifact.display()));
    assert_eq!(
        sha256(&bytes),
        decode_sha256(record.artifact_sha256),
        "candidate artifact digest differs from package record"
    );
    assert_eq!(
        measured_source(&resolution_lock),
        decode_sha256(record.resolution_lock_sha256),
        "candidate dependency-resolution lock differs from package record"
    );
    assert_eq!(
        measured_source(&source_lock),
        decode_sha256(record.source_lock_sha256),
        "candidate source-package lock differs from package record"
    );
    for path in [&manifest, &artifact, &resolution_lock, &source_lock] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    BootProcessPackage {
        bytes,
        version_index: record.package_version_index,
        service_class: record.service_class,
        provenance_root: provenance_root(&[
            measured_source(&resolution_lock),
            measured_source(&source_lock),
        ]),
    }
}

fn configured_file(key: &str, fallback: &Path) -> PathBuf {
    match env::var_os(key) {
        Some(value) => fs::canonicalize(PathBuf::from(value))
            .unwrap_or_else(|error| panic!("failed to resolve {key}: {error}")),
        None => fallback.to_path_buf(),
    }
}

fn provenance_root(digests: &[[u8; 32]]) -> u64 {
    let mut state = 0x4352_5543_4942_4c45_u64;
    for digest in digests {
        for (index, byte) in digest.iter().enumerate() {
            state ^= u64::from(*byte).rotate_left((index as u32) & 63);
            state = state.rotate_left(9).wrapping_mul(0x9e37_79b1_85eb_ca87);
        }
    }
    if state == 0 { 1 } else { state }
}

fn rooted_file(root: &Path, relative: &str) -> PathBuf {
    let candidate = root.join(relative);
    let resolved = fs::canonicalize(&candidate)
        .unwrap_or_else(|error| panic!("failed to resolve {}: {error}", candidate.display()));
    assert!(
        resolved.starts_with(root) && resolved.is_file(),
        "candidate path escapes its package root: {}",
        candidate.display()
    );
    resolved
}

fn valid_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

struct CandidateRecord<'a> {
    schema_version: u16,
    source: &'a str,
    crate_name: &'a str,
    version: &'a str,
    binary: &'a str,
    service_class: u16,
    package_version_index: u16,
    target: &'a str,
    artifact: &'a str,
    artifact_sha256: &'a str,
    resolution_lock_sha256: &'a str,
    source_lock_sha256: &'a str,
}

impl<'a> CandidateRecord<'a> {
    fn parse(text: &'a str) -> Self {
        let mut schema_version = None;
        let mut source = None;
        let mut crate_name = None;
        let mut version = None;
        let mut binary = None;
        let mut service_class = None;
        let mut package_version_index = None;
        let mut target = None;
        let mut artifact = None;
        let mut artifact_sha256 = None;
        let mut resolution_lock_sha256 = None;
        let mut source_lock_sha256 = None;
        for line in text.lines() {
            let (key, value) = line
                .split_once(" = ")
                .unwrap_or_else(|| panic!("invalid candidate record line: {line}"));
            match key {
                "schema_version" => set_once(&mut schema_version, parse_u16(value, key), key),
                "source" => set_once(&mut source, quoted(value, key), key),
                "crate" => set_once(&mut crate_name, quoted(value, key), key),
                "version" => set_once(&mut version, quoted(value, key), key),
                "binary" => set_once(&mut binary, quoted(value, key), key),
                "service_class" => set_once(&mut service_class, parse_u16(value, key), key),
                "package_version_index" => {
                    set_once(&mut package_version_index, parse_u16(value, key), key)
                }
                "target" => set_once(&mut target, quoted(value, key), key),
                "artifact" => set_once(&mut artifact, quoted(value, key), key),
                "artifact_sha256" => set_once(&mut artifact_sha256, quoted(value, key), key),
                "resolution_lock_sha256" => {
                    set_once(&mut resolution_lock_sha256, quoted(value, key), key)
                }
                "source_lock_sha256" => set_once(&mut source_lock_sha256, quoted(value, key), key),
                _ => panic!("unknown candidate record field: {key}"),
            }
        }
        Self {
            schema_version: required(schema_version, "schema_version"),
            source: required(source, "source"),
            crate_name: required(crate_name, "crate"),
            version: required(version, "version"),
            binary: required(binary, "binary"),
            service_class: required(service_class, "service_class"),
            package_version_index: required(package_version_index, "package_version_index"),
            target: required(target, "target"),
            artifact: required(artifact, "artifact"),
            artifact_sha256: required(artifact_sha256, "artifact_sha256"),
            resolution_lock_sha256: required(resolution_lock_sha256, "resolution_lock_sha256"),
            source_lock_sha256: required(source_lock_sha256, "source_lock_sha256"),
        }
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, field: &str) {
    assert!(
        slot.replace(value).is_none(),
        "duplicate candidate field: {field}"
    );
}

fn required<T>(value: Option<T>, field: &str) -> T {
    value.unwrap_or_else(|| panic!("missing candidate field: {field}"))
}

fn quoted<'a>(value: &'a str, field: &str) -> &'a str {
    value
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .filter(|text| !text.contains('"'))
        .unwrap_or_else(|| panic!("candidate field {field} must be one quoted atom"))
}

fn parse_u16(value: &str, field: &str) -> u16 {
    value
        .parse()
        .unwrap_or_else(|_| panic!("candidate field {field} must be a u16"))
}

fn decode_sha256(encoded: &str) -> [u8; 32] {
    assert_eq!(
        encoded.len(),
        64,
        "candidate digest must be 64 hexadecimal characters"
    );
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let pair = &encoded[index * 2..index * 2 + 2];
        *output = u8::from_str_radix(pair, 16)
            .unwrap_or_else(|_| panic!("candidate digest is not hexadecimal"));
    }
    digest
}

fn elf_entry_file_offset(bytes: &[u8]) -> usize {
    assert!(
        bytes.get(..4) == Some(b"\x7fELF") && bytes.get(4) == Some(&2) && bytes.get(5) == Some(&1),
        "Push image must be a little-endian ELF64 artifact"
    );
    let entry = read_u64(bytes, 24);
    let program_offset = usize::try_from(read_u64(bytes, 32)).expect("program table offset");
    let program_entry_size = usize::from(read_u16(bytes, 54));
    let program_count = usize::from(read_u16(bytes, 56));
    assert!(program_entry_size >= 56, "invalid Push program header size");
    for index in 0..program_count {
        let offset = program_offset
            .checked_add(
                index
                    .checked_mul(program_entry_size)
                    .expect("program table index"),
            )
            .expect("program table offset");
        let header = bytes
            .get(offset..offset + 56)
            .expect("Push program header outside artifact");
        let kind = u32::from_le_bytes(header[0..4].try_into().expect("program type"));
        let flags = u32::from_le_bytes(header[4..8].try_into().expect("program flags"));
        let file_offset = u64::from_le_bytes(header[8..16].try_into().expect("file offset"));
        let virtual_address =
            u64::from_le_bytes(header[16..24].try_into().expect("virtual address"));
        let file_size = u64::from_le_bytes(header[32..40].try_into().expect("file size"));
        let memory_size = u64::from_le_bytes(header[40..48].try_into().expect("memory size"));
        let Some(segment_end) = virtual_address.checked_add(memory_size) else {
            continue;
        };
        if kind != 1 || flags & 1 == 0 || entry < virtual_address || entry >= segment_end {
            continue;
        }
        let within_segment = entry - virtual_address;
        assert!(
            within_segment < file_size,
            "Push entry is not backed by executable file bytes"
        );
        return usize::try_from(
            file_offset
                .checked_add(within_segment)
                .expect("Push entry file offset overflow"),
        )
        .expect("Push entry file offset does not fit usize");
    }
    panic!("Push entry is outside an executable load segment");
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("truncated Push ELF field"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("truncated Push ELF field"),
    )
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09_e667_u32,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_length = (bytes.len() as u64).wrapping_mul(8);
    let padded_length = (bytes.len() + 9).div_ceil(64) * 64;
    let mut padded = vec![0_u8; padded_length];
    padded[..bytes.len()].copy_from_slice(bytes);
    padded[bytes.len()] = 0x80;
    padded[padded_length - 8..].copy_from_slice(&bit_length.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let block: &[u8; 64] = chunk.try_into().expect("exact SHA-256 block");
        compress_sha256(&mut state, block);
    }
    let mut digest = [0_u8; 32];
    for (word, output) in state.iter().zip(digest.chunks_exact_mut(4)) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn compress_sha256(state: &mut [u32; 8], block: &[u8; 64]) {
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut words = [0_u32; 64];
    for (word, bytes) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("four-byte SHA-256 word"));
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let choice = (e & f) ^ ((!e) & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let first = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(ROUND[index])
            .wrapping_add(words[index]);
        let second = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}
