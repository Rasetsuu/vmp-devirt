# Diversity builds (reproduction recipe, no binaries)

Same source (`plain_add2.exe`: `solo_add2.c` Virtualization marker + driver),
same VMProtect 3.9.4 (`VMProtect_Con.exe` under Wine), different outputs:

- `repro.exe`: defaults, no project (`VMProtect_Con.exe base.exe repro.exe`).
  Byte-differs from the shipped `vmp_add2.exe`: VMP re-randomizes the VM
  every protection. That alone is a diversity axis.
- `divA.exe`: `-pf pack.vmp` (CompressionMode=1).
- `divB.exe`: `-pf renamed-section.vmp` (VMCodeSectionName=.vmp2).

All print `done e38e3794` (driver loop checksum). Build: copy the plain
binary next to the `.vmp` (InputFileName is relative) and run Con.
Binaries stay out of the repo; regenerate locally (licensed VMP needed).
