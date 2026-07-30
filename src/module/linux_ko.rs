//! Bounded structural preflight for Linux x86-64 `.ko` artifacts.
//!
//! This validates the module metadata and relocation vocabulary before the
//! runtime loader allocates executable memory. It does not resolve symbols or
//! grant lifecycle authority.

use alloc::vec::Vec;

use crate::module::elf::{ElfError, ElfModule, SectionHeader};

const MAXIMUM_MODULE_BYTES: usize = 512 * 1024 * 1024;
const MAXIMUM_RELOCATIONS: usize = 2_000_000;
const SECTION_TYPE_SYMBOL_TABLE: u32 = 2;
const SECTION_TYPE_STRING_TABLE: u32 = 3;
const SECTION_TYPE_RELA: u32 = 4;
const SECTION_FLAG_INFO_LINK: u64 = 0x40;
const SYMBOL_ENTRY_BYTES: usize = 24;
const RELOCATION_ENTRY_BYTES: usize = 24;
const MODVERSION_ENTRY_BYTES: usize = 64;
const MODVERSION_NAME_BYTES: usize = MODVERSION_ENTRY_BYTES - 8;
const CHAINED_MODVERSION_HEADER_BYTES: usize = 8;
const CHAINED_MODVERSION_TERMINATOR_BYTES: usize = 9;
const MAXIMUM_VERSIONED_SYMBOLS: usize = 32_768;

const SECTION_UNDEFINED: u16 = 0;
const SYMBOL_BINDING_GLOBAL: u8 = 1;

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
    DuplicateMetadata,
    MissingSymbolTable,
    InvalidSymbolTable,
    MissingInit,
    InvalidRelocations,
    TooManyRelocations,
    UnsupportedRelocation(u32),
    MissingSymbolVersions,
    InvalidSymbolVersions,
    TooManySymbolVersions,
    DuplicateSymbolVersion,
    UnversionedUndefinedSymbol,
    PlanAllocationFailed,
    InvalidModinfo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSymbolVersion<'a> {
    pub name: &'a [u8],
    pub crc: u32,
}

#[derive(Debug)]
pub struct LinuxKoRequirements<'a> {
    pub manifest: LinuxKoManifest,
    pub name: &'a [u8],
    pub license: &'a [u8],
    pub vermagic: &'a [u8],
    imports: Vec<&'a [u8]>,
    symbols: Vec<LinuxSymbolVersion<'a>>,
}

impl<'a> LinuxKoRequirements<'a> {
    pub fn imports(&self) -> &[&'a [u8]] {
        &self.imports
    }

    pub fn symbols(&self) -> &[LinuxSymbolVersion<'a>] {
        &self.symbols
    }

    pub fn admit<R: LinuxKernelSymbolResolver + ?Sized>(
        &self,
        expected_vermagic: &[u8],
        resolver: &R,
    ) -> Result<LinuxKoAdmission, LinuxKoAdmissionError> {
        if self.vermagic != expected_vermagic {
            return Err(LinuxKoAdmissionError::VermagicMismatch);
        }
        let gpl_compatible = is_gpl_compatible(self.license);
        for (index, required) in self.symbols.iter().enumerate() {
            let resolved = resolver
                .resolve(required.name)
                .ok_or(LinuxKoAdmissionError::MissingExport(index))?;
            if resolved.address == 0 {
                return Err(LinuxKoAdmissionError::ZeroExportAddress(index));
            }
            if resolved.crc != required.crc {
                return Err(LinuxKoAdmissionError::CrcMismatch(index));
            }
            if resolved.class == LinuxExportClass::GplOnly && !gpl_compatible {
                return Err(LinuxKoAdmissionError::GplOnlyExport(index));
            }
            if let Some(namespace) = resolved.namespace {
                if namespace.is_empty() || !self.imports.iter().any(|import| *import == namespace) {
                    return Err(LinuxKoAdmissionError::MissingNamespace(index));
                }
            }
        }
        Ok(LinuxKoAdmission {
            resolved_symbols: self.symbols.len(),
            gpl_compatible,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxExportClass {
    Regular,
    GplOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKernelSymbol<'a> {
    pub address: u64,
    pub crc: u32,
    pub class: LinuxExportClass,
    pub namespace: Option<&'a [u8]>,
}

pub trait LinuxKernelSymbolResolver {
    fn resolve<'a>(&'a self, name: &[u8]) -> Option<LinuxKernelSymbol<'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxKoAdmission {
    pub resolved_symbols: usize,
    pub gpl_compatible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxKoAdmissionError {
    VermagicMismatch,
    MissingExport(usize),
    ZeroExportAddress(usize),
    CrcMismatch(usize),
    GplOnlyExport(usize),
    MissingNamespace(usize),
}

pub fn preflight(bytes: &[u8]) -> Result<LinuxKoManifest, LinuxKoError> {
    if bytes.len() > MAXIMUM_MODULE_BYTES {
        return Err(LinuxKoError::ModuleTooLarge);
    }
    let module = ElfModule::parse(bytes).map_err(LinuxKoError::Elf)?;
    let mut modinfo = None;
    let mut has_this_module = false;
    let mut has_versions = false;
    let mut saw_this_module = false;
    let mut saw_versions = false;
    let mut symbol_table = None;

    for index in 0..module.section_count() {
        let section = module
            .section(index)
            .ok_or(LinuxKoError::Elf(ElfError::InvalidSection))?;
        let name = module.section_name(section).map_err(LinuxKoError::Elf)?;
        match name {
            b".modinfo" => {
                if modinfo.replace(section).is_some() {
                    return Err(LinuxKoError::DuplicateMetadata);
                }
            }
            b".gnu.linkonce.this_module" => {
                if saw_this_module {
                    return Err(LinuxKoError::DuplicateMetadata);
                }
                saw_this_module = true;
                has_this_module = section.size != 0;
            }
            b"__versions" => {
                if saw_versions {
                    return Err(LinuxKoError::DuplicateMetadata);
                }
                saw_versions = true;
                has_versions = section.size != 0;
            }
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

/// Extracts the exact Linux ABI requirements carried by a structurally valid
/// module. This accepts the fixed 64-byte `modversion_info` layout emitted by
/// the qualified Linux 6.12 SDK and the chained, padded layout emitted by the
/// qualified Ubuntu Linux 6.8 SDK. Both decoders validate their complete
/// record stream and reject unknown encodings.
pub fn requirements(bytes: &[u8]) -> Result<LinuxKoRequirements<'_>, LinuxKoError> {
    let manifest = preflight(bytes)?;
    let module = ElfModule::parse(bytes).map_err(LinuxKoError::Elf)?;
    let mut modinfo = None;
    let mut versions = None;
    let mut symbol_table = None;
    for index in 1..module.section_count() {
        let section = module
            .section(index)
            .ok_or(LinuxKoError::Elf(ElfError::InvalidSection))?;
        match module.section_name(section).map_err(LinuxKoError::Elf)? {
            b".modinfo" => modinfo = Some(section),
            b"__versions" => versions = Some(section),
            _ => {}
        }
        if section.section_type == SECTION_TYPE_SYMBOL_TABLE {
            symbol_table = Some(section);
        }
    }

    let modinfo = module
        .section_data(modinfo.ok_or(LinuxKoError::MissingModinfo)?)
        .map_err(LinuxKoError::Elf)?;
    let name = modinfo_value(modinfo, b"name=").ok_or(LinuxKoError::MissingModuleIdentity)?;
    let license = modinfo_value(modinfo, b"license=").ok_or(LinuxKoError::MissingLicense)?;
    let vermagic = modinfo_value(modinfo, b"vermagic=").ok_or(LinuxKoError::MissingVermagic)?;
    let imports = modinfo_values(modinfo, b"import_ns=")?;

    let versions = module
        .section_data(versions.ok_or(LinuxKoError::MissingSymbolVersions)?)
        .map_err(LinuxKoError::Elf)?;
    let symbol_versions = parse_symbol_versions(versions)?;

    require_versions_for_undefined_globals(
        &module,
        symbol_table.ok_or(LinuxKoError::MissingSymbolTable)?,
        &symbol_versions,
    )?;

    Ok(LinuxKoRequirements {
        manifest,
        name,
        license,
        vermagic,
        imports,
        symbols: symbol_versions,
    })
}

fn parse_symbol_versions(versions: &[u8]) -> Result<Vec<LinuxSymbolVersion<'_>>, LinuxKoError> {
    match parse_fixed_symbol_versions(versions) {
        Ok(symbols) => Ok(symbols),
        Err(LinuxKoError::InvalidSymbolVersions) => parse_chained_symbol_versions(versions),
        Err(error) => Err(error),
    }
}

fn parse_fixed_symbol_versions(
    versions: &[u8],
) -> Result<Vec<LinuxSymbolVersion<'_>>, LinuxKoError> {
    if versions.is_empty() || versions.len() % MODVERSION_ENTRY_BYTES != 0 {
        return Err(LinuxKoError::InvalidSymbolVersions);
    }
    let count = versions.len() / MODVERSION_ENTRY_BYTES;
    if count > MAXIMUM_VERSIONED_SYMBOLS {
        return Err(LinuxKoError::TooManySymbolVersions);
    }
    let mut symbol_versions = Vec::new();
    symbol_versions
        .try_reserve_exact(count)
        .map_err(|_| LinuxKoError::PlanAllocationFailed)?;
    for entry in versions.chunks_exact(MODVERSION_ENTRY_BYTES) {
        let crc = read_u64(entry, 0).ok_or(LinuxKoError::InvalidSymbolVersions)?;
        let crc = u32::try_from(crc).map_err(|_| LinuxKoError::InvalidSymbolVersions)?;
        let name = fixed_nul_string(&entry[8..8 + MODVERSION_NAME_BYTES])
            .filter(|name| !name.is_empty())
            .ok_or(LinuxKoError::InvalidSymbolVersions)?;
        push_symbol_version(&mut symbol_versions, name, crc)?;
    }
    Ok(symbol_versions)
}

fn parse_chained_symbol_versions(
    versions: &[u8],
) -> Result<Vec<LinuxSymbolVersion<'_>>, LinuxKoError> {
    if versions.is_empty() {
        return Err(LinuxKoError::InvalidSymbolVersions);
    }
    let mut symbol_versions = Vec::new();
    let mut offset = 0_usize;
    loop {
        let remaining = versions
            .get(offset..)
            .ok_or(LinuxKoError::InvalidSymbolVersions)?;
        let next = read_u32(remaining, 0).ok_or(LinuxKoError::InvalidSymbolVersions)? as usize;
        if next == 0 {
            if remaining.len() != CHAINED_MODVERSION_TERMINATOR_BYTES
                || remaining.iter().any(|byte| *byte != 0)
            {
                return Err(LinuxKoError::InvalidSymbolVersions);
            }
            break;
        }
        if next < CHAINED_MODVERSION_HEADER_BYTES + 4 || next % 4 != 0 || next > remaining.len() {
            return Err(LinuxKoError::InvalidSymbolVersions);
        }
        if symbol_versions.len() >= MAXIMUM_VERSIONED_SYMBOLS {
            return Err(LinuxKoError::TooManySymbolVersions);
        }
        let crc = read_u32(remaining, 4).ok_or(LinuxKoError::InvalidSymbolVersions)?;
        let name = fixed_nul_string(&remaining[CHAINED_MODVERSION_HEADER_BYTES..next])
            .filter(|name| !name.is_empty())
            .ok_or(LinuxKoError::InvalidSymbolVersions)?;
        symbol_versions
            .try_reserve(1)
            .map_err(|_| LinuxKoError::PlanAllocationFailed)?;
        push_symbol_version(&mut symbol_versions, name, crc)?;
        offset = offset
            .checked_add(next)
            .ok_or(LinuxKoError::InvalidSymbolVersions)?;
    }
    if symbol_versions.is_empty() {
        return Err(LinuxKoError::InvalidSymbolVersions);
    }
    Ok(symbol_versions)
}

fn push_symbol_version<'a>(
    versions: &mut Vec<LinuxSymbolVersion<'a>>,
    name: &'a [u8],
    crc: u32,
) -> Result<(), LinuxKoError> {
    if versions.iter().any(|version| version.name == name) {
        return Err(LinuxKoError::DuplicateSymbolVersion);
    }
    versions.push(LinuxSymbolVersion { name, crc });
    Ok(())
}

fn require_versions_for_undefined_globals(
    module: &ElfModule<'_>,
    table: SectionHeader,
    versions: &[LinuxSymbolVersion<'_>],
) -> Result<(), LinuxKoError> {
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
    for symbol in symbols.chunks_exact(SYMBOL_ENTRY_BYTES) {
        let binding = symbol[4] >> 4;
        let section = read_u16(symbol, 6).ok_or(LinuxKoError::InvalidSymbolTable)?;
        if binding != SYMBOL_BINDING_GLOBAL || section != SECTION_UNDEFINED {
            continue;
        }
        let offset = read_u32(symbol, 0).ok_or(LinuxKoError::InvalidSymbolTable)? as usize;
        let name = nul_string(strings, offset)
            .filter(|name| !name.is_empty())
            .ok_or(LinuxKoError::InvalidSymbolTable)?;
        if !versions.iter().any(|version| version.name == name) {
            return Err(LinuxKoError::UnversionedUndefinedSymbol);
        }
    }
    Ok(())
}

fn modinfo_value<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    bytes
        .split(|byte| *byte == 0)
        .find_map(|field| field.strip_prefix(prefix).filter(|value| !value.is_empty()))
}

fn modinfo_values<'a>(bytes: &'a [u8], prefix: &[u8]) -> Result<Vec<&'a [u8]>, LinuxKoError> {
    let mut values = Vec::new();
    for value in bytes
        .split(|byte| *byte == 0)
        .filter_map(|field| field.strip_prefix(prefix))
    {
        if value.is_empty() || values.contains(&value) {
            return Err(LinuxKoError::InvalidModinfo);
        }
        values
            .try_reserve(1)
            .map_err(|_| LinuxKoError::PlanAllocationFailed)?;
        values.push(value);
    }
    Ok(values)
}

fn fixed_nul_string(bytes: &[u8]) -> Option<&[u8]> {
    let length = bytes.iter().position(|byte| *byte == 0)?;
    if bytes[length + 1..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(&bytes[..length])
}

fn is_gpl_compatible(license: &[u8]) -> bool {
    matches!(
        license,
        b"GPL"
            | b"GPL v2"
            | b"GPL and additional rights"
            | b"Dual BSD/GPL"
            | b"Dual MIT/GPL"
            | b"Dual MPL/GPL"
    )
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

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
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
    const LAYOUT_CRC: u32 = 0x1122_3344;
    const EXTERNAL_CRC: u32 = 0xaabb_ccdd;

    #[derive(Clone, Copy)]
    struct TestResolver {
        crc_delta: u32,
        class: LinuxExportClass,
        namespace: Option<&'static [u8]>,
    }

    impl LinuxKernelSymbolResolver for TestResolver {
        fn resolve<'a>(&'a self, name: &[u8]) -> Option<LinuxKernelSymbol<'a>> {
            let crc = match name {
                b"module_layout" => LAYOUT_CRC,
                b"external" => EXTERNAL_CRC,
                _ => return None,
            };
            Some(LinuxKernelSymbol {
                address: 0x1000,
                crc: crc.wrapping_add(self.crc_delta),
                class: self.class,
                namespace: self.namespace,
            })
        }
    }

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
        let strings = b"\0init_module\0cleanup_module\0external\0";
        let names_offset = HEADER_BYTES;
        let info_offset = names_offset + names.len();
        let this_offset = info_offset + info.len();
        let versions_offset = this_offset + 64;
        let strings_offset = versions_offset + 2 * MODVERSION_ENTRY_BYTES;
        let symbols_offset = strings_offset + strings.len();
        let relocations_offset = symbols_offset + 4 * SYMBOL_ENTRY_BYTES;
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
        write_u64(&mut bytes, versions_offset, u64::from(LAYOUT_CRC));
        bytes[versions_offset + 8..versions_offset + 8 + b"module_layout".len()]
            .copy_from_slice(b"module_layout");
        let external_version = versions_offset + MODVERSION_ENTRY_BYTES;
        write_u64(&mut bytes, external_version, u64::from(EXTERNAL_CRC));
        bytes[external_version + 8..external_version + 8 + b"external".len()]
            .copy_from_slice(b"external");

        let init = symbols_offset + SYMBOL_ENTRY_BYTES;
        write_u32(&mut bytes, init, 1);
        bytes[init + 4] = 0x12;
        write_u16(&mut bytes, init + 6, 3);
        let cleanup = symbols_offset + 2 * SYMBOL_ENTRY_BYTES;
        write_u32(&mut bytes, cleanup, 13);
        bytes[cleanup + 4] = 0x12;
        write_u16(&mut bytes, cleanup + 6, 3);
        let external = symbols_offset + 3 * SYMBOL_ENTRY_BYTES;
        write_u32(&mut bytes, external, 28);
        bytes[external + 4] = 0x10;
        write_u16(&mut bytes, external + 6, SECTION_UNDEFINED);
        write_u64(&mut bytes, relocations_offset, 0);
        write_u64(
            &mut bytes,
            relocations_offset + 8,
            (3_u64 << 32) | u64::from(R_X86_64_64),
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
        section(
            &mut bytes,
            table,
            4,
            46,
            1,
            2,
            versions_offset,
            2 * MODVERSION_ENTRY_BYTES,
            0,
            0,
            0,
        );
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
            4 * SYMBOL_ENTRY_BYTES,
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

    fn replace_versions(bytes: &mut [u8], versions: &[u8]) {
        assert!(versions.len() <= 2 * MODVERSION_ENTRY_BYTES);
        let table = bytes.len() - SECTION_COUNT * SECTION_BYTES;
        let section = table + 4 * SECTION_BYTES;
        let offset = read_u64(bytes, section + 24).unwrap() as usize;
        bytes[offset..offset + 2 * MODVERSION_ENTRY_BYTES].fill(0);
        bytes[offset..offset + versions.len()].copy_from_slice(versions);
        write_u64(bytes, section + 32, versions.len() as u64);
    }

    fn chained_versions() -> alloc::vec::Vec<u8> {
        let mut versions = alloc::vec::Vec::new();
        for (name, crc) in [
            (b"module_layout".as_slice(), LAYOUT_CRC),
            (b"external".as_slice(), EXTERNAL_CRC),
        ] {
            let padded_name = (name.len() + 1 + 3) & !3;
            let next = CHAINED_MODVERSION_HEADER_BYTES + padded_name;
            versions.extend_from_slice(&(next as u32).to_le_bytes());
            versions.extend_from_slice(&crc.to_le_bytes());
            versions.extend_from_slice(name);
            versions.resize(versions.len() + padded_name - name.len(), 0);
        }
        versions.resize(versions.len() + CHAINED_MODVERSION_TERMINATOR_BYTES, 0);
        versions
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

    #[test]
    fn exact_vermagic_and_symbol_crcs_are_admitted() {
        let bytes = fixture();
        let requirements = requirements(&bytes).unwrap();
        assert_eq!(requirements.name, b"smoke");
        assert_eq!(requirements.license, b"MIT");
        assert_eq!(requirements.vermagic, b"6.12");
        assert_eq!(requirements.symbols().len(), 2);
        assert!(requirements.imports().is_empty());

        let admission = requirements
            .admit(
                b"6.12",
                &TestResolver {
                    crc_delta: 0,
                    class: LinuxExportClass::Regular,
                    namespace: None,
                },
            )
            .unwrap();
        assert_eq!(admission.resolved_symbols, 2);
        assert!(!admission.gpl_compatible);
    }

    #[test]
    fn accepts_measured_ubuntu_chained_symbol_versions() {
        let mut bytes = fixture();
        replace_versions(&mut bytes, &chained_versions());
        let requirements = requirements(&bytes).unwrap();
        assert_eq!(requirements.symbols().len(), 2);
        assert_eq!(requirements.symbols()[0].name, b"module_layout");
        assert_eq!(requirements.symbols()[0].crc, LAYOUT_CRC);
        assert_eq!(requirements.symbols()[1].name, b"external");
        assert_eq!(requirements.symbols()[1].crc, EXTERNAL_CRC);
    }

    #[test]
    fn chained_symbol_versions_require_exact_links_padding_and_terminator() {
        let mut malformed_link = chained_versions();
        malformed_link[..4].copy_from_slice(&10_u32.to_le_bytes());
        let mut bytes = fixture();
        replace_versions(&mut bytes, &malformed_link);
        assert_eq!(
            requirements(&bytes).err(),
            Some(LinuxKoError::InvalidSymbolVersions)
        );

        let mut malformed_padding = chained_versions();
        malformed_padding[8 + b"module_layout".len() + 1] = 1;
        let mut bytes = fixture();
        replace_versions(&mut bytes, &malformed_padding);
        assert_eq!(
            requirements(&bytes).err(),
            Some(LinuxKoError::InvalidSymbolVersions)
        );

        let mut malformed_terminator = chained_versions();
        malformed_terminator.pop();
        let mut bytes = fixture();
        replace_versions(&mut bytes, &malformed_terminator);
        assert_eq!(
            requirements(&bytes).err(),
            Some(LinuxKoError::InvalidSymbolVersions)
        );
    }

    #[test]
    fn admission_rejects_vermagic_crc_license_and_namespace_drift() {
        let bytes = fixture();
        let requirements = requirements(&bytes).unwrap();
        let regular = TestResolver {
            crc_delta: 0,
            class: LinuxExportClass::Regular,
            namespace: None,
        };
        assert_eq!(
            requirements.admit(b"6.12.1", &regular),
            Err(LinuxKoAdmissionError::VermagicMismatch)
        );
        assert_eq!(
            requirements.admit(
                b"6.12",
                &TestResolver {
                    crc_delta: 1,
                    ..regular
                }
            ),
            Err(LinuxKoAdmissionError::CrcMismatch(0))
        );
        assert_eq!(
            requirements.admit(
                b"6.12",
                &TestResolver {
                    class: LinuxExportClass::GplOnly,
                    ..regular
                }
            ),
            Err(LinuxKoAdmissionError::GplOnlyExport(0))
        );
        assert_eq!(
            requirements.admit(
                b"6.12",
                &TestResolver {
                    namespace: Some(b"DMA_BUF"),
                    ..regular
                }
            ),
            Err(LinuxKoAdmissionError::MissingNamespace(0))
        );
    }

    #[test]
    fn every_undefined_global_requires_a_version_record() {
        let mut bytes = fixture();
        let version_name = bytes
            .windows(b"external".len())
            .rposition(|window| window == b"external")
            .unwrap();
        bytes[version_name] = b'x';
        assert_eq!(
            requirements(&bytes).err(),
            Some(LinuxKoError::UnversionedUndefinedSymbol)
        );
    }
}
