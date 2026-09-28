//! v2 table front-end: 256-entry RVA dispatch tables (VMP 2.x).
//!
//! VMP 2.x dispatches through a table of relative addresses. This front-end
//! scans VMP sections for dense runs of plausible code-pointing RVAs and
//! reports them as handler tables. Bytecode walking itself needs runtime
//! keys (see harness); statically we report table locations.
use anyhow::Result;
use crate::frontend::{FetchHit, VmFrontend};
use crate::pe_loader::PEBinary;

/// Scan one section's bytes (starting at `section_va`) for tables.
pub fn scan_tables_in(data: &[u8], section_va: u64, valid: &dyn Fn(u64) -> bool) -> Vec<u64> {
    let mut out = Vec::new();
    if data.len() < 4 * 64 {
        return out;
    }
    let n = data.len() / 4;
    let mut run_start: Option<usize> = None;
    let flush = |s: usize, i: usize, out: &mut Vec<u64>| {
        if i - s >= 64 {
            out.push(section_va + (s * 4) as u64);
        }
    };
    for i in 0..n {
        let v = u32::from_le_bytes(data[4 * i..4 * i + 4].try_into().unwrap()) as u64;
        if valid(v) {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(s) = run_start.take() {
            flush(s, i, &mut out);
        }
    }
    if let Some(s) = run_start.take() {
        flush(s, n, &mut out);
    }
    out
}

pub struct V2Table;

impl VmFrontend for V2Table {
    fn name(&self) -> &'static str {
        "vmp2-table"
    }
    fn detect(&self, binary: &PEBinary) -> Result<bool> {
        Ok(!handler_addrs_inner(binary)?.is_empty())
    }
    fn fetch_stream(&self, _binary: &PEBinary, _trace: Option<&[u64]>) -> Result<Vec<FetchHit>> {
        Ok(Vec::new())
    }
    fn handler_addrs(&self, binary: &PEBinary, _hits: &[FetchHit]) -> Result<Vec<u64>> {
        handler_addrs_inner(binary)
    }
}

fn handler_addrs_inner(binary: &PEBinary) -> Result<Vec<u64>> {
    let pe = binary.parse_pe()?;
    let base = binary.image_base()?;
    let exec: Vec<(u64, u64)> = pe
        .sections
        .iter()
        .filter(|s| {
            s.size_of_raw_data > 0
                && s.characteristics & 0x20000000 != 0 // IMAGE_SCN_MEM_EXECUTE
        })
        .map(|s| (base + s.virtual_address as u64, s.size_of_raw_data as u64))
        .collect();
    let valid = |v: u64| exec.iter().any(|(b, sz)| *b <= v && v < b + sz);
    let mut out = Vec::new();
    for s in &pe.sections {
        let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
        if !name.to_lowercase().starts_with(".vmp") {
            continue;
        }
        let sz = s.size_of_raw_data as usize;
        if sz == 0 {
            continue;
        }
        let off = s.pointer_to_raw_data as usize;
        let end = off.saturating_add(sz).min(binary.data.len());
        if off < end {
            out.extend(scan_tables_in(&binary.data[off..end], base + s.virtual_address as u64, &valid));
        }
    }
    Ok(out)
}
