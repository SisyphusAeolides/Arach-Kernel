#!/usr/bin/env python3
from pathlib import Path

path = Path("src/linux_file.rs")
text = path.read_text(encoding="utf-8")

old_constants = '''    const OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4101,
        generation: 7,
    };
'''
new_constants = '''    const ROUND_TRIP_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4101,
        generation: 7,
    };
    const GENERATION_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4102,
        generation: 7,
    };
    const DIRECTORY_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4103,
        generation: 7,
    };
    const CLOSE_ALL_OWNER: ProcessHandle = ProcessHandle {
        pid: 0x4104,
        generation: 7,
    };
'''
if text.count(old_constants) != 1:
    raise SystemExit("shared Linux file test owner marker missing")
text = text.replace(old_constants, new_constants)


def function_bounds(source: str, name: str) -> tuple[int, int]:
    marker = f"    fn {name}() {{"
    start = source.find(marker)
    if start < 0:
        raise SystemExit(f"Linux file test {name} missing")
    next_test = source.find("\n    #[test]", start + len(marker))
    if next_test >= 0:
        return start, next_test
    module_end = source.rfind("\n}")
    if module_end <= start:
        raise SystemExit(f"Linux file test {name} has no bounded end")
    return start, module_end


def replace_owner(source: str, name: str, owner: str) -> str:
    start, end = function_bounds(source, name)
    body = source[start:end]
    if "OWNER" not in body:
        raise SystemExit(f"Linux file test {name} has no owner references")
    return source[:start] + body.replace("OWNER", owner) + source[end:]


text = replace_owner(text, "regular_file_round_trip_uses_linux_descriptors", "ROUND_TRIP_OWNER")
text = replace_owner(text, "descriptor_ownership_includes_pid_generation", "GENERATION_OWNER")

start, end = function_bounds(text, "directory_flag_and_open_flag_validation_fail_closed")
new_directory = '''    fn directory_flag_and_open_flag_validation_fail_closed() {
        let root_fd = open(DIRECTORY_OWNER, b"/", O_RDONLY | O_DIRECTORY, 1).unwrap();
        assert!((3..3 + MAXIMUM_FILE_DESCRIPTORS as u32).contains(&root_fd));
        close(DIRECTORY_OWNER, root_fd).unwrap();
        assert_eq!(
            open(DIRECTORY_OWNER, b"/invalid", O_EXCL | O_RDWR, 1),
            Err(FileError::InvalidArgument)
        );
        assert_eq!(
            open(DIRECTORY_OWNER, b"/invalid", O_RDONLY | O_TRUNC, 1),
            Err(FileError::InvalidArgument)
        );
    }
'''.rstrip("\n")
text = text[:start] + new_directory + text[end:]

text = replace_owner(text, "close_all_reclaims_exact_owner_descriptors", "CLOSE_ALL_OWNER")

path.write_text(text, encoding="utf-8")
