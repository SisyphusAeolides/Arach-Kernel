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

old_round_trip = '''    fn regular_file_round_trip_uses_linux_descriptors() {
        let path = b"/linux-file-round-trip";
        let fd = open(OWNER, path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert!((3..3 + MAXIMUM_FILE_DESCRIPTORS as u32).contains(&fd));
        assert_eq!(write(OWNER, fd, b"arach", 2), Ok(5));
        assert_eq!(seek(OWNER, fd, 0, akashic_vfs::seek::FROM_START), Ok(0));
        let mut output = [0_u8; 8];
        assert_eq!(read(OWNER, fd, &mut output), Ok(5));
        assert_eq!(&output[..5], b"arach");
        assert_eq!(fstat(OWNER, fd).unwrap().size_bytes, 5);
        close(OWNER, fd).unwrap();
        unlink(path).unwrap();
    }
'''
new_round_trip = old_round_trip.replace("OWNER", "ROUND_TRIP_OWNER")
if text.count(old_round_trip) != 1:
    raise SystemExit("round-trip Linux file test marker missing")
text = text.replace(old_round_trip, new_round_trip)

old_generation = '''    fn descriptor_ownership_includes_pid_generation() {
        let path = b"/linux-file-generation";
        let fd = open(OWNER, path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        let recycled = ProcessHandle {
            pid: OWNER.pid,
            generation: OWNER.generation + 1,
        };
        assert_eq!(read(recycled, fd, &mut [0_u8; 1]), Err(FileError::BadFileDescriptor));
        assert_eq!(close(recycled, fd), Err(FileError::BadFileDescriptor));
        close(OWNER, fd).unwrap();
        unlink(path).unwrap();
    }
'''
new_generation = old_generation.replace("OWNER", "GENERATION_OWNER")
if text.count(old_generation) != 1:
    raise SystemExit("generation Linux file test marker missing")
text = text.replace(old_generation, new_generation)

old_directory = '''    fn directory_flag_and_open_flag_validation_fail_closed() {
        assert_eq!(
            open(OWNER, b"/", O_RDONLY | O_DIRECTORY, 1).map(|_| ()),
            Ok(())
        );
        let root_fd = open(OWNER, b"/", O_RDONLY | O_DIRECTORY, 1).unwrap();
        close(OWNER, root_fd).unwrap();
        assert_eq!(
            open(OWNER, b"/invalid", O_EXCL | O_RDWR, 1),
            Err(FileError::InvalidArgument)
        );
        assert_eq!(
            open(OWNER, b"/invalid", O_RDONLY | O_TRUNC, 1),
            Err(FileError::InvalidArgument)
        );
    }
'''
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
'''
if text.count(old_directory) != 1:
    raise SystemExit("directory Linux file test marker missing")
text = text.replace(old_directory, new_directory)

old_close_all = '''    fn close_all_reclaims_exact_owner_descriptors() {
        let first_path = b"/linux-file-close-all-a";
        let second_path = b"/linux-file-close-all-b";
        let first = open(OWNER, first_path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        let second = open(OWNER, second_path, O_CREAT | O_EXCL | O_RDWR, 1).unwrap();
        assert_eq!(close_all(OWNER), 2);
        assert_eq!(close(OWNER, first), Err(FileError::BadFileDescriptor));
        assert_eq!(close(OWNER, second), Err(FileError::BadFileDescriptor));
        unlink(first_path).unwrap();
        unlink(second_path).unwrap();
    }
'''
new_close_all = old_close_all.replace("OWNER", "CLOSE_ALL_OWNER")
if text.count(old_close_all) != 1:
    raise SystemExit("close-all Linux file test marker missing")
text = text.replace(old_close_all, new_close_all)

path.write_text(text, encoding="utf-8")
