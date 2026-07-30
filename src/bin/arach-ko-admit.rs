use std::env;
use std::fs;
use std::process::ExitCode;

use arach::module::linux_ko::{LinuxExportClass, LinuxKernelSymbol, LinuxKernelSymbolResolver};

#[derive(Debug)]
struct CatalogEntry {
    name: Vec<u8>,
    crc: u32,
    class: LinuxExportClass,
    namespace: Vec<u8>,
}

#[derive(Default)]
struct Catalog {
    entries: Vec<CatalogEntry>,
}

impl Catalog {
    fn extend(&mut self, path: &std::ffi::OsStr) -> Result<(), String> {
        let bytes = fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.to_string_lossy()))?;
        for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b'\t').collect();
            if fields.len() < 4 || fields[1].is_empty() {
                return Err(format!(
                    "{}:{} has an invalid Module.symvers record",
                    path.to_string_lossy(),
                    line_index + 1
                ));
            }
            let crc = std::str::from_utf8(fields[0])
                .ok()
                .and_then(|value| value.strip_prefix("0x"))
                .and_then(|value| u32::from_str_radix(value, 16).ok())
                .ok_or_else(|| {
                    format!(
                        "{}:{} has an invalid symbol CRC",
                        path.to_string_lossy(),
                        line_index + 1
                    )
                })?;
            let export = fields[3];
            if !export.starts_with(b"EXPORT_SYMBOL") {
                return Err(format!(
                    "{}:{} has an unsupported export class",
                    path.to_string_lossy(),
                    line_index + 1
                ));
            }
            let class = if export.windows(3).any(|window| window == b"GPL") {
                LinuxExportClass::GplOnly
            } else {
                LinuxExportClass::Regular
            };
            let namespace = fields.get(4).copied().unwrap_or_default();
            if let Some(existing) = self.entries.iter().find(|entry| entry.name == fields[1]) {
                if existing.crc != crc || existing.class != class || existing.namespace != namespace
                {
                    return Err(format!(
                        "{}:{} conflicts with an earlier export",
                        path.to_string_lossy(),
                        line_index + 1
                    ));
                }
                continue;
            }
            self.entries.push(CatalogEntry {
                name: fields[1].to_vec(),
                crc,
                class,
                namespace: namespace.to_vec(),
            });
        }
        Ok(())
    }
}

impl LinuxKernelSymbolResolver for Catalog {
    fn resolve<'a>(&'a self, name: &[u8]) -> Option<LinuxKernelSymbol<'a>> {
        let (index, entry) = self
            .entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.name == name)?;
        Some(LinuxKernelSymbol {
            address: index as u64 + 1,
            crc: entry.crc,
            class: entry.class,
            namespace: (!entry.namespace.is_empty()).then_some(entry.namespace.as_slice()),
        })
    }
}

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_else(|| "arach-ko-admit".into());
    let Some(module_path) = arguments.next() else {
        usage(&program);
        return ExitCode::from(2);
    };
    let Some(vermagic_path) = arguments.next() else {
        usage(&program);
        return ExitCode::from(2);
    };
    let symvers: Vec<_> = arguments.collect();
    if symvers.is_empty() {
        usage(&program);
        return ExitCode::from(2);
    }

    let module = match fs::read(&module_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read {}: {error}", module_path.to_string_lossy());
            return ExitCode::FAILURE;
        }
    };
    let mut vermagic = match fs::read(&vermagic_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!(
                "failed to read {}: {error}",
                vermagic_path.to_string_lossy()
            );
            return ExitCode::FAILURE;
        }
    };
    while vermagic
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        vermagic.pop();
    }
    if vermagic.is_empty() {
        eprintln!("expected vermagic is empty");
        return ExitCode::FAILURE;
    }

    let mut catalog = Catalog::default();
    for path in &symvers {
        if let Err(error) = catalog.extend(path) {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    }
    let requirements = match arach::module::linux_ko::requirements(&module) {
        Ok(requirements) => requirements,
        Err(error) => {
            eprintln!("Linux module requirements failed: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    match requirements.admit(&vermagic, &catalog) {
        Ok(admission) => {
            println!(
                "build-admitted {} exports={} gpl_compatible={}",
                String::from_utf8_lossy(requirements.name),
                admission.resolved_symbols,
                admission.gpl_compatible,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Linux module build admission failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn usage(program: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} MODULE.ko VERMAGIC_FILE MODULE.symvers [MODULE.symvers ...]",
        program.to_string_lossy()
    );
}
