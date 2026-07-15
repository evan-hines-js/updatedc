// Bake in a version so the end-to-end test can identify the running artifact.
fn main() {
    let v = std::env::var("APP_VERSION").unwrap_or_else(|_| "0.0.0-dev".into());
    println!("cargo:rustc-env=BAKED_VERSION={v}");
    println!("cargo:rerun-if-env-changed=APP_VERSION");
}
