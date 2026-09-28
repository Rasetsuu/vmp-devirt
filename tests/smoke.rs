//! Fixture tests: synthetic PE64 + hand-built fetch chain. No external files.
use vmp_devirt::frontend::cryptor_miner::{mine_cryptor, low8_of};
use vmp_devirt::frontend::fetch_finder::FetchSite;
use vmp_devirt::backend::value_cryptor::{ValueCryptor, CryptOp, CryptSize};
use vmp_devirt::pe_loader::PEBinary;
use iced_x86::Register;

/// Minimal PE64 image with one `.vmp1` section holding `blob` at VA 0x140001000.
fn fixture_pe(blob: &[u8]) -> PEBinary {
    let mut img = vec![0u8; 0x400];
    img[0] = b'M';
    img[1] = b'Z';
    img[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    img[0x40..0x44].copy_from_slice(b"PE\0\0");
    // COFF: machine AMD64, 1 section
    img[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    img[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    img[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
    img[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes()); // Characteristics
    // Optional64 @0x58, size 0xF0
    img[0x58..0x5A].copy_from_slice(&0x20bu16.to_le_bytes());
    // ImageBase @0x58+24
    img[0x58 + 24..0x58 + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
    // SectionAlignment @0x58+32, FileAlignment @0x58+36
    img[0x58 + 32..0x58 + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    img[0x58 + 36..0x58 + 40].copy_from_slice(&0x200u32.to_le_bytes());
    // SizeOfImage @0x58+56
    img[0x58 + 56..0x58 + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    // Section header @0x58+0xF0 = 0x148
    let sh = 0x148;
    img[sh..sh + 5].copy_from_slice(b".vmp1");
    img[sh + 8..sh + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VSize
    img[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VAddr
    img[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // RawSize
    img[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawPtr
    img[sh + 36..sh + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // exec+read+code
    img[0x200..0x200 + blob.len()].copy_from_slice(blob);
    PEBinary { path: "<fixture>".into(), data: img }
}

#[test]
fn mines_handbuilt_chain() {    // movzx ecx,[rbx]; inc rbx(junk); xor cl,r11b; inc cl; xor cl,6; rol cl,1; jmp +0
    let blob: &[u8] = &[
        0x0F, 0xB6, 0x0B, // movzx ecx, byte ptr [rbx]
        0x48, 0xFF, 0xC3, // inc rbx (skipped junk)
        0x44, 0x30, 0xD9, // xor cl, r11b (key mix)
        0xFE, 0xC1, // inc cl
        0x80, 0xF1, 0x06, // xor cl, 6
        0xD0, 0xC1, // rol cl, 1
        0xEB, 0x00, // jmp +0 (terminal)
    ];
    let va = 0x140001000u64;
    let bin = fixture_pe(blob);
    let site = FetchSite { va, base: Register::RBX, dst: Register::ECX, len: 3 };
    assert_eq!(low8_of(Register::ECX), Register::CL);
    let m = mine_cryptor(&site, &bin).expect("mine");
    assert_eq!(m.key_reg, "r11l");
    assert_eq!(m.steps, 3);
    // Independent oracle: same chain by hand.
    let mut cr = ValueCryptor::new(CryptSize::Byte);
    cr.add(CryptOp::Inc, 0);
    cr.add(CryptOp::Xor, 6);
    cr.add(CryptOp::Rol, 1);
    for (raw, key) in [(0x3eu8, 0xf6u8), (0x00, 0x00), (0xA5, 0x5A)] {
        let expect = cr.encrypt((raw ^ key) as u64) as u8;
        assert_eq!(m.decode(raw, key), expect, "raw {raw:#x} key {key:#x}");
    }
}

#[test]
fn mines_fixture_file() {
    // Checked-in fixture binary: exercises the file-load path in CI.
    let bin = PEBinary::load("tests/fixtures/vmp_test.bin").expect("fixture");
    assert_eq!(bin.image_base().unwrap(), 0x140000000);
    let site = FetchSite { va: 0x140001000, base: Register::RBX, dst: Register::ECX, len: 3 };
    let m = mine_cryptor(&site, &bin).expect("mine file");
    assert_eq!(m.key_reg, "r11l");
    assert_eq!(m.steps, 3);
    // Same chain by hand (must agree with in-memory twin above).
    let mut cr = ValueCryptor::new(CryptSize::Byte);
    cr.add(CryptOp::Inc, 0);
    cr.add(CryptOp::Xor, 6);
    cr.add(CryptOp::Rol, 1);
    assert_eq!(m.decode(0x3e, 0xf6), cr.encrypt(0x3e ^ 0xf6) as u8);
}
