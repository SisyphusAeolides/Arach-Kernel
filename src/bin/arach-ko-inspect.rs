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
    if arguments.next().is_some() {
        eprintln!("usage: {} MODULE.ko", program.to_string_lossy());
        return ExitCode::from(2);
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read {}: {error}", path.to_string_lossy());
            return ExitCode::FAILURE;
        }
    };
    match arach::module::linux_ko::preflight(&bytes) {
        Ok(manifest) => {
            println!("{manifest:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Linux module preflight failed: {error:?}");
            ExitCode::FAILURE
        }
    }
}
