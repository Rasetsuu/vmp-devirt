/// PE Binary Loader
/// 
/// Handles PE binary parsing and VA mapping

use anyhow::{Result, Context};
use goblin::pe::PE;
use std::fs;
use std::path::Path;

/// Loaded PE binary
pub struct PEBinary {
    /// File path
    pub path: String,
    /// Binary data
    pub data: Vec<u8>,
}

impl PEBinary {
    /// Load PE binary from file
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = fs::read(&path)
            .context(format!("Failed to read file: {}", path_str))?;

        // Verify PE header
        let _ = PE::parse(&data)
            .context("Failed to parse PE binary")?;

        Ok(PEBinary {
            path: path_str,
            data,
        })
    }

    /// Parse PE header (on demand)
    pub fn parse_pe(&self) -> Result<PE> {
        PE::parse(&self.data)
            .context("Failed to parse PE binary")
    }

    /// Get section data by name
    pub fn get_section(&self, name: &str) -> Result<Vec<u8>> {
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
    }

    /// Get all section names
    pub fn get_all_sections(&self) -> Result<Vec<String>> {
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
    }

    /// Get image base
    pub fn image_base(&self) -> Result<u64> {
        let pe = self.parse_pe()?;
        Ok(pe.header.optional_header
            .map(|oh| oh.windows_fields.image_base)
            .unwrap_or(0x140000000))
    }

    /// Convert VA to file offset
    pub fn va_to_offset(&self, va: u64) -> Result<usize> {
        let pe = self.parse_pe()?;
        let image_base = pe.header.optional_header
            .map(|oh| oh.windows_fields.image_base)
            .unwrap_or(0x140000000);
        
        for section in &pe.sections {
            let section_start = image_base + section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;
            
            if va >= section_start && va < section_end {
                let offset = va - section_start;
                return Ok(section.pointer_to_raw_data as usize + offset as usize);
            }
        }

        anyhow::bail!("Invalid VA: 0x{:x}", va)
    }

    /// Read bytes from VA
    pub fn read_bytes(&self, va: u64, size: usize) -> Result<Vec<u8>> {
        let offset = self.va_to_offset(va)?;

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

    /// Check if PE is 64-bit
    pub fn is_64bit(&self) -> Result<bool> {
        let pe = self.parse_pe()?;
        Ok(pe.header.optional_header.map(|oh| oh.standard_fields.magic == goblin::pe::optional_header::MAGIC_64).unwrap_or(false))
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
    /// repeated VA reads without re-parsing the PE per call.
    pub fn section_map(&self) -> Result<Vec<(u64, u64, usize)>> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_load() {
        // Test will use real binary
    }
}
