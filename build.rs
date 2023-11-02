use std::process::Command;

fn main() {
    // Compile flatbuffers files
    println!("cargo:rerun-if-changed=fb/tag.fbs");
    println!("cargo:rerun-if-changed=fb/full_tag.fbs");
    println!("cargo:rerun-if-changed=fb/common.fbs");

    let flatc_compiler = flatc::flatc();
    let output = Command::new(flatc_compiler)
        .args(&[
            "-o",
            "src",
            "--rust",
            "--rust-module-root-file",
            "fb/tag.fbs",
            "fb/full_tag.fbs",
            "fb/common.fbs",
        ])
        .output()
        .expect("failed to execute process");
    if !output.status.success() {
        panic!("flatc failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    // Remove generated mod.rs. We have an existing one that we should use instead.
    std::fs::remove_file("src/mod.rs").unwrap();
}
