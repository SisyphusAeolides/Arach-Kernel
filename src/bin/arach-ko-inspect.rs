use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| "arach-ko-inspect".into());
    let Some(path) = arguments.next() else {
        eprintln!(
            "usage: {} MODULE.ko [VERMAGIC_OUTPUT [MODULE_ABI_OUTPUT]]",
            program.to_string_lossy()
        );
        return ExitCode::from(2);
    };
    let vermagic_output = arguments.next();
    let module_abi_output = arguments.next();
    if arguments.next().is_some() {
        eprintln!(
            "usage: {} MODULE.ko [VERMAGIC_OUTPUT [MODULE_ABI_OUTPUT]]",
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
            let module_abi =
                match arach::module::linux_abi::LinuxModuleAbiContract::from_module(&bytes) {
                    Ok(contract) => Some(contract),
                    Err(arach::module::linux_abi::LinuxModuleAbiError::MissingRecord) => None,
                    Err(error) => {
                        eprintln!("Linux module ABI measurement is invalid: {error:?}");
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
            if let Some(output) = module_abi_output {
                let Some(contract) = module_abi else {
                    eprintln!("module lacks .arach.module_abi SDK measurement");
                    return ExitCode::FAILURE;
                };
                let exit_offset = contract
                    .exit_offset
                    .map_or_else(|| "null".to_string(), |value| value.to_string());
                let refcnt_offset = contract
                    .refcnt_offset
                    .map_or_else(|| "null".to_string(), |value| value.to_string());
                let memory_rox_offset = contract
                    .memory_rox_offset
                    .map_or_else(|| "null".to_string(), |value| value.to_string());
                let json = format!(
                    concat!(
                        "{{\n",
                        "  \"format\": \"arach-linux-module-abi-v1\",\n",
                        "  \"module_size\": {},\n",
                        "  \"module_alignment\": {},\n",
                        "  \"module_name_length\": {},\n",
                        "  \"state_offset\": {},\n",
                        "  \"list_offset\": {},\n",
                        "  \"name_offset\": {},\n",
                        "  \"init_offset\": {},\n",
                        "  \"memory_offset\": {},\n",
                        "  \"memory_count\": {},\n",
                        "  \"memory_stride\": {},\n",
                        "  \"memory_base_offset\": {},\n",
                        "  \"memory_rox_offset\": {},\n",
                        "  \"memory_size_offset\": {},\n",
                        "  \"arch_offset\": {},\n",
                        "  \"exit_offset\": {},\n",
                        "  \"refcnt_offset\": {}\n",
                        "}}\n"
                    ),
                    contract.module_size,
                    contract.module_alignment,
                    contract.module_name_length,
                    contract.state_offset,
                    contract.list_offset,
                    contract.name_offset,
                    contract.init_offset,
                    contract.memory_offset,
                    contract.memory_count,
                    contract.memory_stride,
                    contract.memory_base_offset,
                    memory_rox_offset,
                    contract.memory_size_offset,
                    contract.arch_offset,
                    exit_offset,
                    refcnt_offset,
                );
                if let Err(error) = fs::write(&output, json) {
                    eprintln!("failed to write {}: {error}", output.to_string_lossy());
                    return ExitCode::FAILURE;
                }
            }
            println!(
                "{:?} name={} license={} vermagic={} imports={} versioned_symbols={} load_sections={} load_regions={} image_bytes={} core_bytes={} init_bytes={} module_abi={}",
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
                module_abi.is_some(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Linux module preflight failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}
