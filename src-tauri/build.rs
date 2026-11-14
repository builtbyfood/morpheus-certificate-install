// morpheus-certificate-install 0.4.1
//
// On Windows the app manifest (Common Controls v6, which the dialog plugin's TaskDialogIndirect
// needs) is embedded by the linker for every binary in this package, not only the app: the
// tauri::test binaries (tests/commands.rs, tests/engine_e2e.rs) otherwise fail to start with
// STATUS_ENTRYPOINT_NOT_FOUND. tauri-build is told not to add its own copy.
fn main() {
    let mut attributes = tauri_build::Attributes::new();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        attributes = attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
            println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
            println!("cargo:rustc-link-arg=/WX");
        }
    }
    tauri_build::try_build(attributes).expect("tauri-build");
}
