//! v3 FDJ front-end: fetch-scan -> mine -> decode (VMP 3.x).
use anyhow::Result;
use crate::frontend::{FetchHit, VmFrontend};
use crate::frontend::fetch_finder::{scan_fetch_sites_strict, FetchSite};
use crate::frontend::site_emulator::extract_opcode_pure;
use crate::pe_loader::PEBinary;

pub struct V3Fdj;

fn vmp_section_data<'a>(binary: &'a PEBinary) -> Result<(Vec<u8>, u64)> {
    let pe = binary.parse_pe()?;
    let base = binary.image_base()?;
    let mut best: Option<(Vec<u8>, u64)> = None;
    for s in &pe.sections {
        let name = std::str::from_utf8(&s.name).unwrap_or("").trim_end_matches('\0');
        if [".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc"].contains(&name) {
            continue;
        }
        let sz = s.size_of_raw_data as usize;
        if sz == 0 {
            continue;
        }
        let off = s.pointer_to_raw_data as usize;
        let end = off.saturating_add(sz).min(binary.data.len());
        if off >= end {
            continue;
        }
        let cand = (binary.data[off..end].to_vec(), base + s.virtual_address as u64);
        if best.as_ref().map(|(d, _)| d.len()).unwrap_or(0) < cand.0.len() {
            best = Some(cand);
        }
    }
    best.ok_or_else(|| anyhow::anyhow!("no VMP data section"))
}

impl VmFrontend for V3Fdj {
    fn name(&self) -> &'static str {
        "vmp3-fdj"
    }
    fn detect(&self, binary: &PEBinary) -> Result<bool> {
        // VMP 3.x: large non-standard section + strict fetch sites present.
        let (data, base) = match vmp_section_data(binary) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        Ok(!scan_fetch_sites_strict(&data, base).is_empty())
    }
    fn fetch_stream(&self, _binary: &PEBinary, _trace: Option<&[u64]>) -> Result<Vec<FetchHit>> {
        // Static-only v3 decode needs runtime keys; with a trace, hits are
        // decoded per-site by the caller. Without one, report no hits rather
        // than guessing (see harness::snapshot for capture).
        Ok(Vec::new())
    }
    fn handler_addrs(&self, binary: &PEBinary, _hits: &[FetchHit]) -> Result<Vec<u64>> {
        let (data, base) = vmp_section_data(binary)?;
        Ok(scan_fetch_sites_strict(&data, base).into_iter().map(|s: FetchSite| s.va).collect())
    }
}
