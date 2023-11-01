use std::process::Command;

fn main()
{
    println!("cargo:rerun-if-changed=fb/tag.fbs");
    println!("cargo:rerun-if-changed=fb/full_tag.fbs");
    println!("cargo:rerun-if-changed=fb/common.fbs");

    let fc = flatc::flatc();
    let output = Command::new(fc)
        .args(&["-o", "src/serialization", "--rust", "fb/tag.fbs", "fb/full_tag.fbs"])
        .output()
        .expect("failed to execute process");
    if !output.status.success() {
        panic!("flatc failed: {}", String::from_utf8_lossy(&output.stderr));
    }
}
