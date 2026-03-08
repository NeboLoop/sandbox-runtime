use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let vendor_dir = Path::new(&manifest_dir).join("vendor").join("seccomp");

    // Copy vendor seccomp binaries to OUT_DIR if they exist
    for arch in &["x64", "arm64"] {
        let src_dir = vendor_dir.join(arch);
        let dst_dir = Path::new(&out_dir).join("vendor").join("seccomp").join(arch);

        if src_dir.exists() {
            std::fs::create_dir_all(&dst_dir).ok();
            for file in &["unix-block.bpf", "apply-seccomp"] {
                let src = src_dir.join(file);
                if src.exists() {
                    let dst = dst_dir.join(file);
                    std::fs::copy(&src, &dst).ok();
                }
            }
        }
    }

    println!("cargo:rerun-if-changed=vendor/seccomp");
}
