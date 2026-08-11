use std::path::PathBuf;

fn main() {
    let script = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("linker.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=--no-pie");
    println!("cargo:rustc-link-arg=--build-id=none");
    println!("cargo:rustc-link-arg=-zmax-page-size=0x1000");
}
