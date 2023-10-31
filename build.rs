
fn main()
{
    println!("cargo:rerun-if-changed={}", "fb/tag.fbs");
    println!("cargo:rerun-if-changed={}", "fb/full_tag.fbs");
    println!("cargo:rerun-if-changed={}", "fb/common.fbs");
}