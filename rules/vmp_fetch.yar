/* VMP 3.x FDJ fetch-family detection rules.
 * Research/defensive use: triage VMProtect-packed binaries by fetch shape.
 * All byte patterns verified against live-executed fetch sites
 * (movzx + key-mix pairs observed under emulation).
 */
rule vmp3_fdj_fetch_rbp {
    meta:
        description = "VMP 3.x RBP-family fetch: movzx ecx,[rbp+..] + xor cl,dil"
        version = "1.1"
    strings:
        // movzx ecx,byte ptr [rbp+disp8] (SIB form 4C / direct 4D)
        $fetch1 = { 0F B6 4C ?? ?? }
        $fetch2 = { 0F B6 4D ?? }
        // xor cl, dil (observed key-mix)
        $keymix = { 40 32 CF }
    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        (any of ($fetch*) and #keymix > 1)
}

rule vmp3_fdj_fetch_rbx {
    meta:
        description = "VMP 3.x RBX-family fetch: movzx edx,[rbx] + xor dl,bpl"
        version = "1.1"
    strings:
        // movzx edx,byte ptr [rbx] (no-disp 13 / disp8 53)
        $fetch1 = { 0F B6 13 }
        $fetch2 = { 0F B6 53 ?? }
        // xor dl, bpl (observed key-mix)
        $keymix = { 40 32 D5 }
    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and
        (any of ($fetch*) and #keymix > 1)
}

rule vmp3_fdj_fetch_r8 {
    meta:
        description = "VMP 3.x R8-family fetch: movzx edi,[r8]"
        version = "1.1"
    strings:
        // movzx edi, byte ptr [r8]
        $fetch = { 41 0F B6 38 }
    condition:
        uint16(0) == 0x5A4D and filesize < 50MB and #fetch > 3
}

rule vmp3_in_trap {
    meta:
        description = "VMP 3.7+ anti-analysis I/O trap near fetch code"
        version = "1.0"
    strings:
        // in eax, imm8
        $trap = { E4 ?? }
    condition:
        uint16(0) == 0x5A4D and
        (vmp3_fdj_fetch_rbp or vmp3_fdj_fetch_rbx) and #trap > 2
}
