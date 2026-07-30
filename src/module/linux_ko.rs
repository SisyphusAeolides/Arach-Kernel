//! Bounded structural preflight for Linux x86-64 `.ko` artifacts.
//!
//! This validates the module metadata and relocation vocabulary before the
//! runtime loader allocates executable memory. It does not resolve symbols or
//! grant lifecycle authority.

use crate::module::elf::{ElfError, ElfModule, SectionHeader};

const MAXIMUM_MODULE_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_RELOCATIONS: usize = 2_000_000;
const SECTION_TYPE_SYMBOL_TABLE: u32 = 2;
const SECTION_TYPE_STRING_TABLE: u32 = 3;
const SECTION_TYPE_RELA: u32 = 4;
const SECTION_FLAG_INFO_LINK: u64 = 0x40;
const SYMBOL_ENTRY_BYTES: usize = 24;
const RELOCATION_ENTRY_BYTES: usize = 24;

const R_X86_64_64: u32 = 1;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_32: u32 = 10;
const R_X86_64_32S: u32 = 11;
const R_X86_64_PC64: u32 = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKoManifest {
    pub section_count: usize,
    pub relocation_count: usize,
    pub relocation_kinds: u64,
    pub has_symbol_versions: bool,
    pub has_cleanup: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxKoError {
    Elf(ElfError),
    ModuleTooLarge,
    MissingModinfo,
    MissingModuleIdentity,
    MissingLicense,
    MissingVermagic,
    MissingThisModule,
    MissingSymbolTable,
    InvalidSymbolTable,
    MissingInit,
    InvalidRelocations,
    TooManyRelocations,
    UnsupportedRelocation(u32),
}

pub fn preflight(bytes: &[u8]) -> Result<LinuxKoManifest, LinuxKoError> {
    if bytes.len() > MAXIMUM_MODULE_BYTES {
        return Err(LinuxKoError::ModuleTooLarge);
    }
    let module = ElfModule::parse(bytes).map_err(LinuxKoError::Elf)?;
    let mut modinfo = None;
    let mut has_this_module = false;
    let mut has_versions = false;
    let mut symbol_table = None;

    for index in 0..module.section_count() {
        let section = module
            .section(index)
            .ok_or(LinuxKoError::Elf(ElfError::InvalidSection))?;
        let name = module.section_name(section).map_err(LinuxKoError::Elf)?;
        match name {
            b".modinfo" => modinfo = Some(section),
            b".gnu.linkonce.this_module" => has_this_module = section.size != 0,
            b"__versions" => has_versions = section.size != 0,
            _ => {}
        }
        if section.section_type == SECTION_TYPE_SYMBOL_TABLE {
            if symbol_table.replace((index, section)).is_some() {
                return Err(LinuxKoError::InvalidSymbolTable);
            }
        }
    }

    let modinfo = modinfo.ok_or(LinuxKoError::MissingModinfo)?;
    let modinfo = module.section_data(modinfo).map_err(LinuxKoError::Elf)?;
    if !has_nul_field(modinfo, b"name=") {
        return Err(LinuxKoError::MissingModuleIdentity);
    }
    if !has_nul_field(modinfo, b"license=") {
        return Err(LinuxKoError::MissingLicense);
    }
    if !has_nul_field(modinfo, b"vermagic=") {
        return Err(LinuxKoError::MissingVermagic);
    }
    if !has_this_module {
        return Err(LinuxKoError::MissingThisModule);
    }

    let (symbol_table_index, symbol_table) =
        symbol_table.ok_or(LinuxKoError::MissingSymbolTable)?;
    let (symbol_count, has_init, has_cleanup) = inspect_symbols(&module, symbol_table)?;
    if !has_init {
        return Err(LinuxKoError::MissingInit);
    }

    let mut relocation_count = 0_usize;
    let mut relocation_kinds = 0_u64;
    for index in 1..module.section_count() {
        let section = module
            .section(index)
            .ok_or(LinuxKoError::InvalidRelocations)?;
        if section.section_type == SECTION_TYPE_RELA {
            inspect_relocations(
                &module,
                section,
                symbol_table_index,
                symbol_count,
                &mut relocation_count,
                &mut relocation_kinds,
            )?;
        }
    }

    Ok(LinuxKoManifest {
        section_count: module.section_count(),
        relocation_count,
        relocation_kinds,
        has_symbol_versions: has_versions,
        has_cleanup,
    })
}

fn inspect_relocations(
    module: &ElfModule<'_>,
    section: SectionHeader,
    symbol_table_index: usize,
    symbol_count: usize,
    total: &mut usize,
    kinds: &mut u64,
) -> Result<(), LinuxKoError> {
    if section.entry_size as usize != RELOCATION_ENTRY_BYTES
        || section.size % RELOCATION_ENTRY_BYTES as u64 != 0
        || section.flags != SECTION_FLAG_INFO_LINK
        || section.address != 0
        || section.alignment != 8
        || section.link as usize != symbol_table_index
    {
        return Err(LinuxKoError::InvalidRelocations);
    }
    let target = module
        .section(section.info as usize)
        .filter(|_| section.info != 0)
        .ok_or(LinuxKoError::InvalidRelocations)?;
    let bytes = module.section_data(section).map_err(LinuxKoError::Elf)?;
    let entries = bytes.len() / RELOCATION_ENTRY_BYTES;
    *total = total
        .checked_add(entries)
        .ok_or(LinuxKoError::TooManyRelocations)?;
    if *total > MAXIMUM_RELOCATIONS {
        return Err(LinuxKoError::TooManyRelocations);
    }
    for entry in bytes.chunks_exact(RELOCATION_ENTRY_BYTES) {
        let offset = read_u64(entry, 0).ok_or(LinuxKoError::InvalidRelocations)?;
        let information = read_u64(entry, 8).ok_or(LinuxKoError::InvalidRelocations)?;
        let symbol_index =
            usize::try_from(information >> 32).map_err(|_| LinuxKoError::InvalidRelocations)?;
        let kind = information as u32;
        let width = match kind {
            R_X86_64_64 | R_X86_64_PC64 => 8,
            R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_32 | R_X86_64_32S => 4,
            _ => return Err(LinuxKoError::UnsupportedRelocation(kind)),
        };
        if symbol_index >= symbol_count
            || offset
                .checked_add(width)
                .is_none_or(|end| end > target.size)
        {
            return Err(LinuxKoError::InvalidRelocations);
        }
        *kinds |= 1_u64 << kind;
    }
    Ok(())
}

fn inspect_symbols(
    module: &ElfModule<'_>,
    table: SectionHeader,
) -> Result<(usize, bool, bool), LinuxKoError> {
    if table.entry_size as usize != SYMBOL_ENTRY_BYTES
        || table.size == 0
        || table.size % SYMBOL_ENTRY_BYTES as u64 != 0
        || table.flags != 0
        || table.address != 0
        || table.alignment != 8
    {
        return Err(LinuxKoError::InvalidSymbolTable);
    }
    let strings = module
        .section(table.link as usize)
        .filter(|section| section.section_type == SECTION_TYPE_STRING_TABLE)
        .ok_or(LinuxKoError::InvalidSymbolTable)?;
    let strings = module
        .section_data(strings)
        .map_err(|_| LinuxKoError::InvalidSymbolTable)?;
    let symbols = module
        .section_data(table)
        .map_err(|_| LinuxKoError::InvalidSymbolTable)?;
    let symbol_count = symbols.len() / SYMBOL_ENTRY_BYTES;
    if strings.first() != Some(&0) || table.info as usize > symbol_count {
        return Err(LinuxKoError::InvalidSymbolTable);
    }
    let mut has_init = false;
    let mut has_cleanup = false;
    for symbol in symbols.chunks_exact(SYMBOL_ENTRY_BYTES) {
        let offset = read_u32(symbol, 0).ok_or(LinuxKoError::InvalidSymbolTable)? as usize;
        let name = nul_string(strings, offset).ok_or(LinuxKoError::InvalidSymbolTable)?;
        has_init |= name == b"init_module";
        has_cleanup |= name == b"cleanup_module";
    }
    Ok((symbol_count, has_init, has_cleanup))
}

fn has_nul_field(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes
        .split(|byte| *byte == 0)
        .any(|field| field.starts_with(prefix) && field.len() > prefix.len())
}

fn nul_string(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let suffix = bytes.get(offset..)?;
    let length = suffix.iter().position(|byte| *byte == 0)?;
    Some(&suffix[..length])
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

    const HEADER_BYTES: usize = 64;
    const SECTION_BYTES: usize = 64;
    const SECTION_COUNT: usize = 8;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn section(
        bytes: &mut [u8],
        table: usize,
        index: usize,
        name: u32,
        kind: u32,
        flags: u64,
        offset: usize,
        size: usize,
        link: u32,
        info: u32,
        entry_size: u64,
    ) {
        let base = table + index * SECTION_BYTES;
        write_u32(bytes, base, name);
        write_u32(bytes, base + 4, kind);
        write_u64(bytes, base + 8, flags);
        write_u64(bytes, base + 24, offset as u64);
        write_u64(bytes, base + 32, size as u64);
        write_u32(bytes, base + 40, link);
        write_u32(bytes, base + 44, info);
        write_u64(bytes, base + 48, 8);
        write_u64(bytes, base + 56, entry_size);
    }

    fn fixture() -> alloc::vec::Vec<u8> {
        let names = b"\0.shstrtab\0.modinfo\0.gnu.linkonce.this_module\0__versions\0.strtab\0.symtab\0.rela.gnu.linkonce.this_module\0";
        let info = b"license=MIT\0name=smoke\0vermagic=6.12\0";
        let strings = b"\0init_module\0cleanup_module\0";
        let names_offset = HEADER_BYTES;
        let info_offset = names_offset + names.len();
        let this_offset = info_offset + info.len();
        let versions_offset = this_offset + 64;
        let strings_offset = versions_offset + 64;
        let symbols_offset = strings_offset + strings.len();
        let relocations_offset = symbols_offset + 3 * SYMBOL_ENTRY_BYTES;
        let table = (relocations_offset + RELOCATION_ENTRY_BYTES + 7) & !7;
        let mut bytes = alloc::vec![0_u8; table + SECTION_COUNT * SECTION_BYTES];

        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        write_u16(&mut bytes, 16, 1);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 40, table as u64);
        write_u16(&mut bytes, 52, HEADER_BYTES as u16);
        write_u16(&mut bytes, 58, SECTION_BYTES as u16);
        write_u16(&mut bytes, 60, SECTION_COUNT as u16);
        write_u16(&mut bytes, 62, 1);

        bytes[names_offset..info_offset].copy_from_slice(names);
        bytes[info_offset..this_offset].copy_from_slice(info);
        bytes[strings_offset..symbols_offset].copy_from_slice(strings);

        let init = symbols_offset + SYMBOL_ENTRY_BYTES;
        write_u32(&mut bytes, init, 1);
        bytes[init + 4] = 0x12;
        write_u16(&mut bytes, init + 6, 3);
        let cleanup = symbols_offset + 2 * SYMBOL_ENTRY_BYTES;
        write_u32(&mut bytes, cleanup, 13);
        bytes[cleanup + 4] = 0x12;
        write_u16(&mut bytes, cleanup + 6, 3);
        write_u64(&mut bytes, relocations_offset, 0);
        write_u64(
            &mut bytes,
            relocations_offset + 8,
            (1_u64 << 32) | u64::from(R_X86_64_64),
        );

        section(
            &mut bytes,
            table,
            1,
            1,
            3,
            0,
            names_offset,
            names.len(),
            0,
            0,
            0,
        );
        section(
            &mut bytes,
            table,
            2,
            11,
            1,
            2,
            info_offset,
            info.len(),
            0,
            0,
            0,
        );
        section(&mut bytes, table, 3, 20, 1, 3, this_offset, 64, 0, 0, 0);
        section(&mut bytes, table, 4, 46, 1, 2, versions_offset, 64, 0, 0, 0);
        section(
            &mut bytes,
            table,
            5,
            57,
            3,
            0,
            strings_offset,
            strings.len(),
            0,
            0,
            0,
        );
        section(
            &mut bytes,
            table,
            6,
            65,
            2,
            0,
            symbols_offset,
            3 * SYMBOL_ENTRY_BYTES,
            5,
            1,
            SYMBOL_ENTRY_BYTES as u64,
        );
        section(
            &mut bytes,
            table,
            7,
            73,
            SECTION_TYPE_RELA,
            SECTION_FLAG_INFO_LINK,
            relocations_offset,
            RELOCATION_ENTRY_BYTES,
            6,
            3,
            RELOCATION_ENTRY_BYTES as u64,
        );
        bytes
    }

    #[test]
    fn accepts_versioned_linux_module_metadata_and_lifecycle() {
        let manifest = preflight(&fixture()).unwrap();
        assert_eq!(manifest.section_count, SECTION_COUNT);
        assert_eq!(manifest.relocation_count, 1);
        assert_eq!(manifest.relocation_kinds, 1_u64 << R_X86_64_64);
        assert!(manifest.has_symbol_versions);
        assert!(manifest.has_cleanup);
    }

    #[test]
    fn missing_vermagic_is_rejected() {
        let mut bytes = fixture();
        let marker = bytes
            .windows(b"vermagic=".len())
            .position(|window| window == b"vermagic=")
            .unwrap();
        bytes[marker] = b'x';
        assert_eq!(preflight(&bytes), Err(LinuxKoError::MissingVermagic));
    }

    #[test]
    fn relocation_symbol_table_and_target_are_bound() {
        let mut bytes = fixture();
        let relocation = bytes.len() - SECTION_COUNT * SECTION_BYTES + 7 * SECTION_BYTES;
        write_u32(&mut bytes, relocation + 40, 5);
        assert_eq!(preflight(&bytes), Err(LinuxKoError::InvalidRelocations));

        let mut bytes = fixture();
        let relocation = bytes.len() - SECTION_COUNT * SECTION_BYTES + 7 * SECTION_BYTES;
        write_u32(&mut bytes, relocation + 44, 0);
        assert_eq!(preflight(&bytes), Err(LinuxKoError::InvalidRelocations));
    }
}
