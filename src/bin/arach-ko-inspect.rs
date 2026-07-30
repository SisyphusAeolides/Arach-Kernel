use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| "arach-ko-inspect".into());
    let Some(path) = arguments.next() else {
        eprintln!("usage: {} MODULE.ko", program.to_string_lossy());
        return ExitCode::from(2);
    };
    let vermagic_output = arguments.next();
    if arguments.next().is_some() {
        eprintln!(
            "usage: {} MODULE.ko [VERMAGIC_OUTPUT]",
            program.to_string_lossy()
        );
        return ExitCode::from(2);
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read {}: {error}", path.to_string_lossy());
            return ExitCode::FAILURE;
        }
    };
    match arach::module::linux_ko::requirements(&bytes) {
        Ok(requirements) => {
            let blueprint = match arach::module::linux_loader::LinuxKoLoadBlueprint::parse(&bytes) {
                Ok(blueprint) => blueprint,
                Err(error) => {
                    eprintln!("Linux module load-layout planning failed: {error:?}");
                    return ExitCode::FAILURE;
                }
            };
            if let Some(output) = vermagic_output {
                let mut measured = requirements.vermagic.to_vec();
                measured.push(b'\n');
                if let Err(error) = fs::write(&output, measured) {
                    eprintln!("failed to write {}: {error}", output.to_string_lossy());
                    return ExitCode::FAILURE;
                }
            }
            println!(
                "{:?} name={} license={} vermagic={} imports={} versioned_symbols={} load_sections={} load_regions={} image_bytes={} core_bytes={} init_bytes={}",
                requirements.manifest,
                String::from_utf8_lossy(requirements.name),
                String::from_utf8_lossy(requirements.license),
                String::from_utf8_lossy(requirements.vermagic),
                requirements.imports().len(),
                requirements.symbols().len(),
                blueprint.sections().len(),
                blueprint.regions().len(),
                blueprint.image_size(),
                blueprint.core_size(),
                blueprint.init_size(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Linux module preflight failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}
