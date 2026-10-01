/// PE/ELF Binary Loader (format-agnostic since the Tigress frontend).
///
/// `PEBinary` keeps its name for API stability; it loads PE *or* ELF
/// (goblin sniffs the magic). All VA-mapping APIs work on both: PE uses
/// image_base + section RVAs, ELF uses absolute `sh_addr`s. PE-only
/// helpers (`parse_pe`) stay PE-only — VMP frontends keep using them.

use anyhow::{Result, Context};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Object format sniffed at load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinFmt {
    Pe,
    Elf,
}

/// Loaded PE/ELF binary
pub struct PEBinary {
    /// File path
    pub path: String,
    /// Binary data
    pub data: Vec<u8>,
    /// Sniffed format
    pub fmt: BinFmt,
}

impl PEBinary {
    /// Load PE/ELF binary from file (magic-sniffed via goblin).
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = fs::read(&path)
            .context(format!("Failed to read file: {}", path_str))?;

        // Sniff: PE first (historic default), then ELF.
        if PE::parse(&data).is_ok() {
            return Ok(PEBinary { path: path_str, data, fmt: BinFmt::Pe });
        }
        if goblin::elf::Elf::parse(&data).is_ok() {
            return Ok(PEBinary { path: path_str, data, fmt: BinFmt::Elf });
        }
        anyhow::bail!("not a PE or ELF binary: {}", path_str)
    }

    /// Format sniffed at load.
    pub fn fmt(&self) -> BinFmt {
        self.fmt
    }

    /// Parse PE header (on demand; PE only)
    pub fn parse_pe(&self) -> Result<PE> {
        PE::parse(&self.data)
            .context("Failed to parse PE binary")
    }

    /// Parse ELF header (on demand; ELF only)
    pub fn parse_elf(&self) -> Result<goblin::elf::Elf> {
        goblin::elf::Elf::parse(&self.data)
            .context("Failed to parse ELF binary")
    }

    /// Get section data by name (PE or ELF section headers)
    pub fn get_section(&self, name: &str) -> Result<Vec<u8>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            for section in &pe.sections {
                let section_name = std::str::from_utf8(&section.name[..])
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if section_name == name {
                    let start = section.pointer_to_raw_data as usize;
                    let end = start + section.size_of_raw_data as usize;
                    return Ok(self.data.get(start..end).unwrap_or(&[]).to_vec());
                }
            }
            anyhow::bail!("Section not found: {}", name)
        } else {
            let elf = self.parse_elf()?;
            for sh in &elf.section_headers {
                if &elf.shdr_strtab[sh.sh_name] == name {
                    let start = sh.sh_offset as usize;
                    let end = start + sh.sh_size as usize;
                    return Ok(self.data.get(start..end).unwrap_or(&[]).to_vec());
                }
            }
            anyhow::bail!("Section not found: {}", name)
        }
    }

    /// Get all section names
    pub fn get_all_sections(&self) -> Result<Vec<String>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            let mut sections = Vec::new();
            for section in &pe.sections {
                let name = std::str::from_utf8(&section.name[..])
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .to_string();
                if !name.is_empty() {
                    sections.push(name);
                }
            }
            Ok(sections)
        } else {
            let elf = self.parse_elf()?;
            Ok(elf.section_headers.iter()
                .map(|sh| elf.shdr_strtab[sh.sh_name].to_string())
                .filter(|n| !n.is_empty())
                .collect())
        }
    }

    /// Get image base (PE optional-header base; ELF lowest ALLOC sh_addr)
    pub fn image_base(&self) -> Result<u64> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            Ok(pe.header.optional_header
                .map(|oh| oh.windows_fields.image_base)
                .unwrap_or(0x140000000))
        } else {
            let elf = self.parse_elf()?;
            elf.section_headers.iter()
                .filter(|sh| sh.sh_addr != 0 && sh.sh_size != 0)
                .map(|sh| sh.sh_addr)
                .min()
                .context("no loaded ELF sections")
        }
    }

    /// Convert VA to file offset, verifying `size` bytes of file backing.
    /// Packed sections report virtual sizes far beyond file data;
    /// unmapped regions are zeros, not neighboring file bytes.
    /// ELF sections carry absolute sh_addrs (no image-base add).
    pub fn va_to_offset_sized(&self, va: u64, size: usize) -> Result<usize> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            let image_base = pe.header.optional_header
                .map(|oh| oh.windows_fields.image_base)
                .unwrap_or(0x140000000);
            for section in &pe.sections {
                let section_start = image_base + section.virtual_address as u64;
                let section_end = section_start + section.virtual_size as u64;
                if va >= section_start && va < section_end {
                    let offset = va - section_start;
                    let file_off = section.pointer_to_raw_data as usize + offset as usize;
                    let raw_end = section.pointer_to_raw_data as usize + section.size_of_raw_data as usize;
                    if file_off + size > raw_end {
                        anyhow::bail!("VA {:#x}+{:#x} exceeds file backing", va, size)
                    }
                    return Ok(file_off);
                }
            }
            anyhow::bail!("Invalid VA: 0x{:x}", va)
        } else {
            let elf = self.parse_elf()?;
            for sh in &elf.section_headers {
                if sh.sh_addr == 0 || sh.sh_size == 0 {
                    continue;
                }
                // NOBITS (.bss) has no file backing: match but refuse reads.
                if va >= sh.sh_addr && va < sh.sh_addr + sh.sh_size {
                    if sh.sh_type == goblin::elf::section_header::SHT_NOBITS {
                        anyhow::bail!("VA {:#x} in NOBITS (no file backing)", va)
                    }
                    let off = sh.sh_offset as usize + (va - sh.sh_addr) as usize;
                    if off + size > sh.sh_offset as usize + sh.sh_size as usize {
                        anyhow::bail!("VA {:#x}+{:#x} exceeds file backing", va, size)
                    }
                    return Ok(off);
                }
            }
            anyhow::bail!("Invalid VA: 0x{:x}", va)
        }
    }

    /// Convert VA to file offset (single byte; for ranges use sized).
    pub fn va_to_offset(&self, va: u64) -> Result<usize> {
        self.va_to_offset_sized(va, 1)
    }

    /// Read bytes from VA
    pub fn read_bytes(&self, va: u64, size: usize) -> Result<Vec<u8>> {
        let offset = self.va_to_offset_sized(va, size)?;

        Ok(self.data.get(offset..offset + size)
            .context("Out of bounds read")?
            .to_vec())
    }

    /// Read u8 from VA
    pub fn read_u8(&self, va: u64) -> Result<u8> {
        Ok(self.read_bytes(va, 1)?[0])
    }

    /// Read u32 from VA (little-endian)
    pub fn read_u32(&self, va: u64) -> Result<u32> {
        let bytes = self.read_bytes(va, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Check if binary is 64-bit (PE magic or ELF class)
    pub fn is_64bit(&self) -> Result<bool> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            Ok(pe.header.optional_header.map(|oh| oh.standard_fields.magic == goblin::pe::optional_header::MAGIC_64).unwrap_or(false))
        } else {
            Ok(self.parse_elf()?.is_64)
        }
    }

    /// Read u64 from VA (little-endian)
    pub fn read_u64(&self, va: u64) -> Result<u64> {
        let bytes = self.read_bytes(va, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
    /// Section map parsed once: (va_start, va_end, file_offset).
    /// End covers max(virtual_size, size_of_raw_data); use for fast
    /// repeated VA reads without re-parsing the header per call.
    /// (ELF: absolute sh_addrs, same tuple shape.)
    pub fn section_map(&self) -> Result<Vec<(u64, u64, usize)>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            let image_base = pe.header.optional_header
                .map(|oh| oh.windows_fields.image_base)
                .unwrap_or(0x140000000);
            let mut out = Vec::new();
            for s in &pe.sections {
                let start = image_base + s.virtual_address as u64;
                let span = s.virtual_size.max(s.size_of_raw_data) as u64;
                out.push((start, start + span, s.pointer_to_raw_data as usize));
            }
            Ok(out)
        } else {
            let elf = self.parse_elf()?;
            let mut out = Vec::new();
            for sh in &elf.section_headers {
                if sh.sh_addr == 0 || sh.sh_size == 0
                    || sh.sh_type == goblin::elf::section_header::SHT_NOBITS
                {
                    continue;
                }
                out.push((sh.sh_addr, sh.sh_addr + sh.sh_size, sh.sh_offset as usize));
            }
            Ok(out)
        }
    }

    /// Read bytes via a pre-parsed [`section_map`](Self::section_map).
    pub fn read_via(&self, map: &[(u64, u64, usize)], va: u64, n: usize) -> Option<Vec<u8>> {
        for (start, end, raw) in map {
            if va >= *start && va + n as u64 <= *end {
                let off = *raw + (va - start) as usize;
                return self.data.get(off..off + n).map(|b| b.to_vec());
            }
        }
        None
    }

    /// Emulator-facing section list: (name, va, file_off, raw_len, virt_len).
    /// PE: base + RVA, raw = size_of_raw_data, virt = max(virt, raw).
    /// ELF: absolute sh_addr; NOBITS reported with raw_len 0 (zero-fill).
    pub fn map_sections(&self) -> Result<Vec<(String, u64, usize, usize, usize)>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_pe()?;
            let base = self.image_base()?;
            let mut out = Vec::new();
            for s in &pe.sections {
                let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0').to_string();
                let raw = s.size_of_raw_data as usize;
                let virt = (s.virtual_size.max(s.size_of_raw_data)) as usize;
                if virt == 0 {
                    continue;
                }
                out.push((name, base + s.virtual_address as u64, s.pointer_to_raw_data as usize, raw, virt));
            }
            Ok(out)
        } else {
            let elf = self.parse_elf()?;
            let mut out = Vec::new();
            for sh in &elf.section_headers {
                if sh.sh_addr == 0 || sh.sh_size == 0 {
                    continue;
                }
                let name = elf.shdr_strtab[sh.sh_name].to_string();
                let nobits = sh.sh_type == goblin::elf::section_header::SHT_NOBITS;
                out.push((name, sh.sh_addr, sh.sh_offset as usize,
                    if nobits { 0 } else { sh.sh_size as usize }, sh.sh_size as usize));
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_load() {
        // Test will use real binary
    }
}
