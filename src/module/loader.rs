const ELF_HEADER_LENGTH: usize = 64;
const PROGRAM_HEADER_LENGTH: usize = 56;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_SHARED_OBJECT: u16 = 3;
const MACHINE_X86_64: u16 = 62;
const SEGMENT_LOAD: u32 = 1;
const SEGMENT_EXECUTABLE: u32 = 1 << 0;
const SEGMENT_WRITABLE: u32 = 1 << 1;
const SEGMENT_READABLE: u32 = 1 << 2;
const SEGMENT_FLAGS: u32 = SEGMENT_EXECUTABLE | SEGMENT_WRITABLE | SEGMENT_READABLE;
const SEGMENT_INTERPRETER: u32 = 3;
const MAXIMUM_LOAD_SEGMENTS: usize = 16;
const MAXIMUM_INTERPRETER_PATH_BYTES: usize = 255;
/// Position-independent user images are mapped at one deterministic, isolated
/// base.  The address stays well above the fixed bootstrap heap/stack and
/// below the Linux anonymous-mapping arena.  ASLR is deliberately not part of
/// the measured-image contract yet; reproducibility requires one load bias.
pub const POSITION_INDEPENDENT_LOAD_BASE: u64 = 0x0000_1000_0000;
/// Deterministic load base for a measured ELF runtime linker.  It is isolated
/// from the main ET_DYN image and remains below the Linux heap/mmap arenas.
pub const RUNTIME_LINKER_LOAD_BASE: u64 = 0x0000_1800_0000;
const PAGE_SIZE: u64 = 0x1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub file_offset: usize,
    pub file_size: usize,
    pub virtual_address: u64,
    pub memory_size: u64,
    pub alignment: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl LoadSegment {
    const EMPTY: Self = Self {
        file_offset: 0,
        file_size: 0,
        virtual_address: 0,
        memory_size: 0,
        alignment: 0,
        readable: false,
        writable: false,
        executable: false,
    };

    fn end(self) -> Option<u64> {
        self.virtual_address.checked_add(self.memory_size)
    }

    fn contains(self, address: u64) -> bool {
        self.virtual_address <= address && self.end().is_some_and(|end| address < end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadPlan {
    segments: [LoadSegment; MAXIMUM_LOAD_SEGMENTS],
    segment_count: usize,
    pub image_start: u64,
    pub image_end: u64,
    pub entry_point: u64,
    /// Runtime bias applied to ET_DYN virtual addresses.  ET_EXEC images use
    /// zero.  The bias is part of the validated plan so the installer and the
    /// measurement record cannot disagree about the entry address.
    pub load_bias: u64,
    /// A `PT_INTERP` segment names a separately measured runtime linker.
    /// Admission policy decides whether the plan is a standalone image or the
    /// main half of a composite dynamic execution.
    pub requires_runtime_linker: bool,
    position_independent: bool,
    program_header_address: Option<u64>,
    program_header_count: u16,
    interpreter_file_offset: usize,
    interpreter_path_length: usize,
}

impl LoadPlan {
    pub fn parse(bytes: &[u8]) -> Result<Self, LoaderError> {
        Self::parse_with_position_independent_base(bytes, POSITION_INDEPENDENT_LOAD_BASE)
    }

    /// Parses an ELF runtime linker at its isolated deterministic base.
    pub fn parse_runtime_linker(bytes: &[u8]) -> Result<Self, LoaderError> {
        let plan = Self::parse_with_position_independent_base(bytes, RUNTIME_LINKER_LOAD_BASE)?;
        if !plan.position_independent || plan.requires_runtime_linker {
            return Err(LoaderError::InvalidRuntimeLinker);
        }
        Ok(plan)
    }

    fn parse_with_position_independent_base(
        bytes: &[u8],
        position_independent_base: u64,
    ) -> Result<Self, LoaderError> {
        validate_header(bytes)?;
        if position_independent_base & (PAGE_SIZE - 1) != 0 {
            return Err(LoaderError::InvalidImageBias);
        }
        let program_header_offset =
            usize::try_from(read_u64(bytes, 32).ok_or(LoaderError::Truncated)?)
                .map_err(|_| LoaderError::InvalidProgramHeaders)?;
        let program_header_size = read_u16(bytes, 54).ok_or(LoaderError::Truncated)? as usize;
        let program_header_count_raw = read_u16(bytes, 56).ok_or(LoaderError::Truncated)?;
        let program_header_count = usize::from(program_header_count_raw);
        if program_header_size != PROGRAM_HEADER_LENGTH || program_header_count == 0 {
            return Err(LoaderError::InvalidProgramHeaders);
        }
        let table_size = program_header_count
            .checked_mul(program_header_size)
            .ok_or(LoaderError::InvalidProgramHeaders)?;
        if program_header_offset
            .checked_add(table_size)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(LoaderError::InvalidProgramHeaders);
        }

        let image_type = read_u16(bytes, 16).ok_or(LoaderError::Truncated)?;
        let position_independent = image_type == ELF_TYPE_SHARED_OBJECT;
        let mut plan = Self {
            segments: [LoadSegment::EMPTY; MAXIMUM_LOAD_SEGMENTS],
            segment_count: 0,
            image_start: u64::MAX,
            image_end: 0,
            entry_point: read_u64(bytes, 24).ok_or(LoaderError::Truncated)?,
            load_bias: 0,
            requires_runtime_linker: false,
            position_independent,
            program_header_address: None,
            program_header_count: program_header_count_raw,
            interpreter_file_offset: 0,
            interpreter_path_length: 0,
        };
        for index in 0..program_header_count {
            let offset = program_header_offset + index * program_header_size;
            let header = &bytes[offset..offset + program_header_size];
            let segment_type = read_u32(header, 0).ok_or(LoaderError::InvalidProgramHeaders)?;
            if segment_type == SEGMENT_INTERPRETER {
                if plan.requires_runtime_linker {
                    return Err(LoaderError::DuplicateInterpreter);
                }
                let file_offset =
                    usize::try_from(read_u64(header, 8).ok_or(LoaderError::InvalidInterpreter)?)
                        .map_err(|_| LoaderError::InvalidInterpreter)?;
                let file_size =
                    usize::try_from(read_u64(header, 32).ok_or(LoaderError::InvalidInterpreter)?)
                        .map_err(|_| LoaderError::InvalidInterpreter)?;
                let memory_size =
                    usize::try_from(read_u64(header, 40).ok_or(LoaderError::InvalidInterpreter)?)
                        .map_err(|_| LoaderError::InvalidInterpreter)?;
                let path = bytes
                    .get(
                        file_offset
                            ..file_offset
                                .checked_add(file_size)
                                .ok_or(LoaderError::InvalidInterpreter)?,
                    )
                    .ok_or(LoaderError::InvalidInterpreter)?;
                if file_size < 2
                    || file_size > MAXIMUM_INTERPRETER_PATH_BYTES + 1
                    || memory_size != file_size
                    || path.last() != Some(&0)
                    || !is_canonical_absolute_path(&path[..path.len() - 1])
                {
                    return Err(LoaderError::InvalidInterpreter);
                }
                plan.requires_runtime_linker = true;
                plan.interpreter_file_offset = file_offset;
                plan.interpreter_path_length = file_size - 1;
            }
            if segment_type != SEGMENT_LOAD {
                continue;
            }
            let flags = read_u32(header, 4).ok_or(LoaderError::InvalidSegment)?;
            let file_offset = read_u64(header, 8).ok_or(LoaderError::InvalidSegment)?;
            let virtual_address = read_u64(header, 16).ok_or(LoaderError::InvalidSegment)?;
            let file_size = read_u64(header, 32).ok_or(LoaderError::InvalidSegment)?;
            let memory_size = read_u64(header, 40).ok_or(LoaderError::InvalidSegment)?;
            let alignment = read_u64(header, 48).ok_or(LoaderError::InvalidSegment)?;
            if memory_size == 0 {
                continue;
            }
            if flags & !SEGMENT_FLAGS != 0
                || flags & (SEGMENT_WRITABLE | SEGMENT_EXECUTABLE)
                    == (SEGMENT_WRITABLE | SEGMENT_EXECUTABLE)
            {
                return Err(LoaderError::WriteExecuteSegment);
            }
            if file_size > memory_size
                || (alignment > 1 && !alignment.is_power_of_two())
                || (alignment > 1 && file_offset % alignment != virtual_address % alignment)
            {
                return Err(LoaderError::InvalidSegment);
            }
            let file_offset =
                usize::try_from(file_offset).map_err(|_| LoaderError::InvalidSegment)?;
            let file_size = usize::try_from(file_size).map_err(|_| LoaderError::InvalidSegment)?;
            if file_offset
                .checked_add(file_size)
                .is_none_or(|end| end > bytes.len())
                || virtual_address.checked_add(memory_size).is_none()
            {
                return Err(LoaderError::InvalidSegment);
            }
            let segment = LoadSegment {
                file_offset,
                file_size,
                virtual_address,
                memory_size,
                alignment,
                readable: flags & SEGMENT_READABLE != 0,
                writable: flags & SEGMENT_WRITABLE != 0,
                executable: flags & SEGMENT_EXECUTABLE != 0,
            };
            if plan.segments[..plan.segment_count]
                .iter()
                .any(|existing| ranges_overlap(*existing, segment))
            {
                return Err(LoaderError::OverlappingSegments);
            }
            let slot = plan
                .segments
                .get_mut(plan.segment_count)
                .ok_or(LoaderError::TooManySegments)?;
            *slot = segment;
            plan.segment_count += 1;
            plan.image_start = plan.image_start.min(segment.virtual_address);
            plan.image_end = plan
                .image_end
                .max(segment.end().ok_or(LoaderError::InvalidSegment)?);
        }
        if plan.segment_count == 0 {
            return Err(LoaderError::MissingLoadSegment);
        }
        if !plan
            .segments()
            .iter()
            .any(|segment| segment.executable && segment.contains(plan.entry_point))
        {
            return Err(LoaderError::InvalidEntryPoint);
        }
        if position_independent {
            let raw_start = align_down(plan.image_start);
            let load_bias = position_independent_base
                .checked_sub(raw_start)
                .ok_or(LoaderError::InvalidImageBias)?;
            for segment in &mut plan.segments[..plan.segment_count] {
                segment.virtual_address = segment
                    .virtual_address
                    .checked_add(load_bias)
                    .ok_or(LoaderError::InvalidImageBias)?;
            }
            plan.image_start = plan
                .image_start
                .checked_add(load_bias)
                .ok_or(LoaderError::InvalidImageBias)?;
            plan.image_end = plan
                .image_end
                .checked_add(load_bias)
                .ok_or(LoaderError::InvalidImageBias)?;
            plan.entry_point = plan
                .entry_point
                .checked_add(load_bias)
                .ok_or(LoaderError::InvalidImageBias)?;
            plan.load_bias = load_bias;
        }
        let program_header_end = program_header_offset
            .checked_add(table_size)
            .ok_or(LoaderError::InvalidProgramHeaders)?;
        plan.program_header_address = plan.segments().iter().find_map(|segment| {
            let segment_file_end = segment.file_offset.checked_add(segment.file_size)?;
            if program_header_offset >= segment.file_offset
                && program_header_end <= segment_file_end
            {
                segment
                    .virtual_address
                    .checked_add((program_header_offset - segment.file_offset) as u64)
            } else {
                None
            }
        });
        Ok(plan)
    }

    pub fn segments(&self) -> &[LoadSegment] {
        &self.segments[..self.segment_count]
    }

    pub fn segment_data<'a>(
        &self,
        bytes: &'a [u8],
        segment: LoadSegment,
    ) -> Result<&'a [u8], LoaderError> {
        bytes
            .get(segment.file_offset..segment.file_offset + segment.file_size)
            .ok_or(LoaderError::InvalidSegment)
    }

    pub fn entry_file_offset(&self) -> Result<usize, LoaderError> {
        let segment = self
            .segments()
            .iter()
            .copied()
            .find(|segment| segment.executable && segment.contains(self.entry_point))
            .ok_or(LoaderError::InvalidEntryPoint)?;
        let within_segment = usize::try_from(self.entry_point - segment.virtual_address)
            .map_err(|_| LoaderError::InvalidEntryPoint)?;
        if within_segment >= segment.file_size {
            return Err(LoaderError::InvalidEntryPoint);
        }
        segment
            .file_offset
            .checked_add(within_segment)
            .ok_or(LoaderError::InvalidEntryPoint)
    }

    pub fn interpreter_path<'a>(&self, bytes: &'a [u8]) -> Result<Option<&'a [u8]>, LoaderError> {
        if !self.requires_runtime_linker {
            return Ok(None);
        }
        bytes
            .get(
                self.interpreter_file_offset
                    ..self
                        .interpreter_file_offset
                        .checked_add(self.interpreter_path_length)
                        .ok_or(LoaderError::InvalidInterpreter)?,
            )
            .map(Some)
            .ok_or(LoaderError::InvalidInterpreter)
    }

    pub const fn is_position_independent(&self) -> bool {
        self.position_independent
    }

    pub const fn program_header_address(&self) -> Option<u64> {
        self.program_header_address
    }

    pub const fn program_header_count(&self) -> u16 {
        self.program_header_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoaderError {
    Truncated,
    InvalidMagic,
    UnsupportedFormat,
    InvalidHeader,
    InvalidProgramHeaders,
    InvalidSegment,
    WriteExecuteSegment,
    OverlappingSegments,
    TooManySegments,
    MissingLoadSegment,
    InvalidEntryPoint,
    InvalidImageBias,
    InvalidInterpreter,
    DuplicateInterpreter,
    InvalidRuntimeLinker,
}

const fn align_down(address: u64) -> u64 {
    address & !(PAGE_SIZE - 1)
}

fn is_canonical_absolute_path(path: &[u8]) -> bool {
    if path.is_empty()
        || path[0] != b'/'
        || path.contains(&0)
        || core::str::from_utf8(path).is_err()
    {
        return false;
    }
    if path == b"/" {
        return true;
    }
    if path.last() == Some(&b'/') {
        return false;
    }
    path[1..]
        .split(|byte| *byte == b'/')
        .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn validate_header(bytes: &[u8]) -> Result<(), LoaderError> {
    if bytes.len() < ELF_HEADER_LENGTH {
        return Err(LoaderError::Truncated);
    }
    if bytes.get(..4) != Some(b"\x7fELF") {
        return Err(LoaderError::InvalidMagic);
    }
    let image_type = read_u16(bytes, 16);
    if bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || !matches!(
            image_type,
            Some(ELF_TYPE_EXECUTABLE | ELF_TYPE_SHARED_OBJECT)
        )
        || read_u16(bytes, 18) != Some(MACHINE_X86_64)
        || read_u32(bytes, 20) != Some(1)
    {
        return Err(LoaderError::UnsupportedFormat);
    }
    if read_u16(bytes, 52) != Some(ELF_HEADER_LENGTH as u16) {
        return Err(LoaderError::InvalidHeader);
    }
    Ok(())
}

fn ranges_overlap(left: LoadSegment, right: LoadSegment) -> bool {
    let Some(left_end) = left.end() else {
        return true;
    };
    let Some(right_end) = right.end() else {
        return true;
    };
    left.virtual_address < right_end && right.virtual_address < left_end
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_object(flags: u32) -> [u8; 132] {
        let mut bytes = [0_u8; 132];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ELF_TYPE_SHARED_OBJECT.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(0x1000_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(1_u16).to_le_bytes());

        let header = &mut bytes[64..120];
        header[0..4].copy_from_slice(&SEGMENT_LOAD.to_le_bytes());
        header[4..8].copy_from_slice(&flags.to_le_bytes());
        header[8..16].copy_from_slice(&(128_u64).to_le_bytes());
        header[16..24].copy_from_slice(&(0x1000_u64).to_le_bytes());
        header[32..40].copy_from_slice(&(4_u64).to_le_bytes());
        header[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        header[48..56].copy_from_slice(&(1_u64).to_le_bytes());
        bytes[128..].copy_from_slice(&[1, 2, 3, 4]);
        bytes
    }

    #[test]
    fn builds_a_bounded_read_execute_plan() {
        let bytes = shared_object(SEGMENT_READABLE | SEGMENT_EXECUTABLE);
        let plan = LoadPlan::parse(&bytes).unwrap();
        assert_eq!(plan.image_start, POSITION_INDEPENDENT_LOAD_BASE);
        assert_eq!(plan.image_end, POSITION_INDEPENDENT_LOAD_BASE + 0x1000);
        assert_eq!(plan.entry_point, POSITION_INDEPENDENT_LOAD_BASE);
        assert_eq!(plan.load_bias, POSITION_INDEPENDENT_LOAD_BASE - 0x1000);
        assert_eq!(plan.segments().len(), 1);
        assert!(!plan.requires_runtime_linker);
        assert_eq!(plan.entry_file_offset(), Ok(128));
        assert_eq!(
            plan.segment_data(&bytes, plan.segments()[0]).unwrap(),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn rejects_write_execute_segments() {
        let bytes = shared_object(SEGMENT_READABLE | SEGMENT_WRITABLE | SEGMENT_EXECUTABLE);
        assert_eq!(
            LoadPlan::parse(&bytes),
            Err(LoaderError::WriteExecuteSegment)
        );
    }

    #[test]
    fn accepts_a_fixed_address_static_executable() {
        let mut bytes = shared_object(SEGMENT_READABLE | SEGMENT_EXECUTABLE);
        bytes[16..18].copy_from_slice(&ELF_TYPE_EXECUTABLE.to_le_bytes());
        let plan = LoadPlan::parse(&bytes).unwrap();
        assert_eq!(plan.load_bias, 0);
        assert_eq!(plan.image_start, 0x1000);
    }

    #[test]
    fn keeps_pt_interp_images_fail_closed_for_the_runtime_linker() {
        let mut bytes = [0_u8; 188];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ELF_TYPE_SHARED_OBJECT.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(0x1000_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(2_u16).to_le_bytes());

        let load = &mut bytes[64..120];
        load[0..4].copy_from_slice(&SEGMENT_LOAD.to_le_bytes());
        load[4..8].copy_from_slice(&(SEGMENT_READABLE | SEGMENT_EXECUTABLE).to_le_bytes());
        load[8..16].copy_from_slice(&(176_u64).to_le_bytes());
        load[16..24].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[32..40].copy_from_slice(&(4_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(1_u64).to_le_bytes());
        let interpreter = &mut bytes[120..176];
        interpreter[0..4].copy_from_slice(&SEGMENT_INTERPRETER.to_le_bytes());
        interpreter[8..16].copy_from_slice(&(180_u64).to_le_bytes());
        interpreter[32..40].copy_from_slice(&(7_u64).to_le_bytes());
        interpreter[40..48].copy_from_slice(&(7_u64).to_le_bytes());
        bytes[176..180].copy_from_slice(&[1, 2, 3, 4]);
        bytes[180..187].copy_from_slice(b"/ld.so\0");

        let plan = LoadPlan::parse(&bytes).unwrap();
        assert!(plan.requires_runtime_linker);
        assert_eq!(plan.interpreter_path(&bytes), Ok(Some(&b"/ld.so"[..])));
        assert_eq!(plan.entry_file_offset(), Ok(176));
    }

    #[test]
    fn isolates_a_position_independent_runtime_linker() {
        let bytes = shared_object(SEGMENT_READABLE | SEGMENT_EXECUTABLE);
        let plan = LoadPlan::parse_runtime_linker(&bytes).unwrap();
        assert_eq!(plan.image_start, RUNTIME_LINKER_LOAD_BASE);
        assert_eq!(plan.entry_point, RUNTIME_LINKER_LOAD_BASE);
        assert!(plan.is_position_independent());
    }

    #[test]
    fn rejects_an_unterminated_interpreter_path() {
        let mut bytes = [0_u8; 188];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ELF_TYPE_SHARED_OBJECT.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(0x1000_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(2_u16).to_le_bytes());
        let load = &mut bytes[64..120];
        load[0..4].copy_from_slice(&SEGMENT_LOAD.to_le_bytes());
        load[4..8].copy_from_slice(&(SEGMENT_READABLE | SEGMENT_EXECUTABLE).to_le_bytes());
        load[8..16].copy_from_slice(&(176_u64).to_le_bytes());
        load[16..24].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[32..40].copy_from_slice(&(4_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(1_u64).to_le_bytes());
        let interpreter = &mut bytes[120..176];
        interpreter[0..4].copy_from_slice(&SEGMENT_INTERPRETER.to_le_bytes());
        interpreter[8..16].copy_from_slice(&(180_u64).to_le_bytes());
        interpreter[32..40].copy_from_slice(&(6_u64).to_le_bytes());
        interpreter[40..48].copy_from_slice(&(6_u64).to_le_bytes());
        bytes[176..180].copy_from_slice(&[1, 2, 3, 4]);
        bytes[180..186].copy_from_slice(b"/ld.so");

        assert_eq!(
            LoadPlan::parse(&bytes),
            Err(LoaderError::InvalidInterpreter)
        );
    }

    #[test]
    fn rejects_a_noncanonical_interpreter_path() {
        let mut bytes = [0_u8; 196];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ELF_TYPE_SHARED_OBJECT.to_le_bytes());
        bytes[18..20].copy_from_slice(&MACHINE_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&(1_u32).to_le_bytes());
        bytes[24..32].copy_from_slice(&(0x1000_u64).to_le_bytes());
        bytes[32..40].copy_from_slice(&(64_u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(64_u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(56_u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(2_u16).to_le_bytes());
        let load = &mut bytes[64..120];
        load[0..4].copy_from_slice(&SEGMENT_LOAD.to_le_bytes());
        load[4..8].copy_from_slice(&(SEGMENT_READABLE | SEGMENT_EXECUTABLE).to_le_bytes());
        load[8..16].copy_from_slice(&(176_u64).to_le_bytes());
        load[16..24].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[32..40].copy_from_slice(&(4_u64).to_le_bytes());
        load[40..48].copy_from_slice(&(0x1000_u64).to_le_bytes());
        load[48..56].copy_from_slice(&(1_u64).to_le_bytes());
        let interpreter = &mut bytes[120..176];
        interpreter[0..4].copy_from_slice(&SEGMENT_INTERPRETER.to_le_bytes());
        interpreter[8..16].copy_from_slice(&(180_u64).to_le_bytes());
        interpreter[32..40].copy_from_slice(&(14_u64).to_le_bytes());
        interpreter[40..48].copy_from_slice(&(14_u64).to_le_bytes());
        bytes[176..180].copy_from_slice(&[1, 2, 3, 4]);
        bytes[180..194].copy_from_slice(b"/lib/../ld.so\0");

        assert_eq!(
            LoadPlan::parse(&bytes),
            Err(LoaderError::InvalidInterpreter)
        );
    }
}
