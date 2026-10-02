/// PE/ELF Binary Loader (format-agnostic since the Tigress frontend).
///
/// `PEBinary` keeps its name for API stability; it loads PE *or* ELF
/// (manual PE parse + goblin ELF). All VA-mapping APIs work on both: PE uses
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

/// Tolerant manual PE section entry: no UTF-8 validation, no string-table
/// or import parsing. Ultra/mutated builds (1.54→3.10, costum) use random
/// or non-UTF8 section names that goblin rejects outright; mapping only
/// needs RVAs, sizes and file offsets, so parse those directly.
#[derive(Debug, Clone)]
pub struct ManualSec {
    /// Lossy section name (matching/display only, never for mapping).
    pub name_lossy: String,
    /// Section RVA (virtual address minus image base).
    pub rva: u32,
    /// Virtual size.
    pub vsize: u32,
    /// File offset of raw data.
    pub raw_ptr: u32,
    /// Raw data size in file.
    pub raw_size: u32,
    /// Section characteristics (execute flag etc.).
    pub chars: u32,
}

/// Minimal manual PE header: image base, bitness, entry, sections.
#[derive(Debug, Clone)]
pub struct ManualPe {
    /// Image base from the optional header.
    pub image_base: u64,
    /// True for PE32+ (0x20b), false for PE32 (0x10b).
    pub is64: bool,
    /// AddressOfEntryPoint RVA.
    pub entry_rva: u32,
    /// Section table in file order.
    pub sections: Vec<ManualSec>,
}

fn rd_u16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .context("manual PE: truncated u16")
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .context("manual PE: truncated u32")
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(data: &[u8], off: usize) -> Result<u64> {
    data.get(off..off + 8)
        .context("manual PE: truncated u64")
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Parse PE headers tolerantly (MZ → e_lfanew → COFF → optional → sections).
/// Returns an error (not a panic) on any truncation or bad magic.
pub fn parse_manual_pe(data: &[u8]) -> Result<ManualPe> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        anyhow::bail!("manual PE: no MZ magic");
    }
    let e_lfanew = rd_u32(data, 0x3c)? as usize;
    if e_lfanew.checked_add(6).map(|e| e > data.len()).unwrap_or(true)
        || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0"
    {
        anyhow::bail!("manual PE: bad PE signature");
    }
    let coff = e_lfanew + 4;
    let nsec = rd_u16(data, coff + 2)? as usize;
    let opth = rd_u16(data, coff + 16)? as usize;
    if nsec == 0 || nsec > 96 {
        anyhow::bail!("manual PE: bad section count {}", nsec);
    }
    let opt = coff + 20;
    let magic = rd_u16(data, opt)?;
    let is64 = match magic {
        0x20b => true,
        0x10b => false,
        _ => anyhow::bail!("manual PE: bad optional magic {:#x}", magic),
    };
    let entry_rva = rd_u32(data, opt + 16)?;
    let image_base = if is64 {
        rd_u64(data, opt + 24)?
    } else {
        rd_u32(data, opt + 28)? as u64
    };
    let mut sections = Vec::with_capacity(nsec);
    let mut off = opt + opth;
    for _ in 0..nsec {
        if off + 40 > data.len() {
            anyhow::bail!("manual PE: truncated section table");
        }
        let raw_name = &data[off..off + 8];
        let name_lossy = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();
        sections.push(ManualSec {
            name_lossy,
            vsize: rd_u32(data, off + 8)?,
            rva: rd_u32(data, off + 12)?,
            raw_size: rd_u32(data, off + 16)?,
            raw_ptr: rd_u32(data, off + 20)?,
            chars: rd_u32(data, off + 36)?,
        });
        off += 40;
    }
    Ok(ManualPe { image_base, is64, entry_rva, sections })
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
    /// Load PE/ELF binary (manual PE parse first, ELF via goblin).
    /// Goblin rejects mutated section names as `invalid utf8`; the manual
    /// parser only reads RVAs/sizes/offsets, so ultra builds load.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = fs::read(&path)
            .context(format!("Failed to read file: {}", path_str))?;

        // Tolerant PE first (historic default), then ELF.
        if parse_manual_pe(&data).is_ok() {
            return Ok(PEBinary { path: path_str, data, fmt: BinFmt::Pe });
        }
        if goblin::elf::Elf::parse(&data).is_ok() {
            return Ok(PEBinary { path: path_str, data, fmt: BinFmt::Elf });
        }
        // Re-run for a useful error (manual PE reason + ELF magic).
        let pe_err = parse_manual_pe(&data).err()
            .map(|e| format!("{:?}", e))
            .unwrap_or_else(|| "unknown".to_string());
        let elf_err = format!("{:?}", goblin::elf::Elf::parse(&data).err());
        anyhow::bail!("not a PE ({}) or ELF ({}) binary: {}", pe_err, elf_err, path_str)
    }

    /// Tolerant manual PE header (no UTF-8/import parsing; PE only).
    pub fn parse_manual(&self) -> Result<ManualPe> {
        if self.fmt != BinFmt::Pe {
            anyhow::bail!("not a PE binary: {}", self.path)
        }
        parse_manual_pe(&self.data)
    }

    /// Format sniffed at load.
    pub fn fmt(&self) -> BinFmt {
        self.fmt
    }

    /// Parse PE header via goblin (on demand; PE only).
    /// May fail on mutated section names; prefer `parse_manual`.
    pub fn parse_pe(&self) -> Result<PE> {
        PE::parse(&self.data)
            .context("Failed to parse PE binary")
    }

    /// Parse ELF header (on demand; ELF only)
    pub fn parse_elf(&self) -> Result<goblin::elf::Elf> {
        goblin::elf::Elf::parse(&self.data)
            .context("Failed to parse ELF binary")
    }

    /// Get section data by name (PE or ELF section headers).
    /// PE uses the tolerant manual parser (mutated names load).
    pub fn get_section(&self, name: &str) -> Result<Vec<u8>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_manual()?;
            for section in &pe.sections {
                if section.name_lossy == name {
                    let start = section.raw_ptr as usize;
                    let end = start + section.raw_size as usize;
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

    /// Get all section names (PE: lossy names, mutated builds included).
    pub fn get_all_sections(&self) -> Result<Vec<String>> {
        if self.fmt == BinFmt::Pe {
            let pe = self.parse_manual()?;
            Ok(pe.sections.iter()
                .map(|s| s.name_lossy.clone())
                .filter(|n| !n.is_empty())
                .collect())
        } else {
            let elf = self.parse_elf()?;
            Ok(elf.section_headers.iter()
                .map(|sh| elf.shdr_strtab[sh.sh_name].to_string())
                .filter(|n| !n.is_empty())
                .collect())
        }
    }

    /// Get image base (PE optional-header base; ELF lowest ALLOC sh_addr).
    pub fn image_base(&self) -> Result<u64> {
        if self.fmt == BinFmt::Pe {
            Ok(self.parse_manual()?.image_base)
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
            let pe = self.parse_manual()?;
            for section in &pe.sections {
                let section_start = pe.image_base + section.rva as u64;
                let section_end = section_start + section.vsize as u64;
                if va >= section_start && va < section_end {
                    let offset = va - section_start;
                    let file_off = section.raw_ptr as usize + offset as usize;
                    let raw_end = section.raw_ptr as usize + section.raw_size as usize;
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

    /// Check if binary is 64-bit (PE magic or ELF class).
    pub fn is_64bit(&self) -> Result<bool> {
        if self.fmt == BinFmt::Pe {
            Ok(self.parse_manual()?.is64)
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
            let pe = self.parse_manual()?;
            let mut out = Vec::new();
            for s in &pe.sections {
                let start = pe.image_base + s.rva as u64;
                let span = s.vsize.max(s.raw_size) as u64;
                out.push((start, start + span, s.raw_ptr as usize));
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
            let pe = self.parse_manual()?;
            let mut out = Vec::new();
            for s in &pe.sections {
                let raw = s.raw_size as usize;
                let virt = s.vsize.max(s.raw_size) as usize;
                if virt == 0 {
                    continue;
                }
                out.push((s.name_lossy.clone(), pe.image_base + s.rva as u64, s.raw_ptr as usize, raw, virt));
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
