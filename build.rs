// Link system libatomic for unicorn-engine-sys static archive
// (__atomic_*_16 used by QEMU cpu helpers).
fn main() {
    println!("cargo:rustc-link-lib=atomic");
}
