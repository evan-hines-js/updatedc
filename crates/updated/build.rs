//! Package the exact dynamically linked FIPS module, keeping its bytes unmodified.
use std::{collections::BTreeMap, env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile = out.ancestors().nth(3).expect("Cargo profile directory");
    let mut libraries = BTreeMap::new();
    let metadata: BTreeMap<_, _> = env::vars().collect();
    // aws-lc-rs forwards metadata for the backend it actually selected. Depending on that
    // metadata avoids separately pinning a sys-crate version that could drift from crypto.
    let selected: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| key.starts_with("DEP_AWS_LC_RS_") && key.ends_with("_LINK_KIND"))
        .collect();
    assert_eq!(
        selected.len(),
        1,
        "exactly one crypto backend must expose its link metadata"
    );
    for (key, value) in selected {
        if value == "static" {
            continue;
        }
        assert_eq!(value, "dylib", "unsupported crypto linkage");
        let prefix = key.strip_suffix("LINK_KIND").unwrap();
        let libdir = PathBuf::from(&metadata[&format!("{prefix}LIBDIR")]);
        let link = PathBuf::from(&metadata[&format!("{prefix}LIBCRYPTO_PATH")]);
        let runtime = if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
            let name = link.with_extension("dll").file_name().unwrap().to_owned();
            let sibling = libdir.join(&name);
            if sibling.is_file() {
                sibling
            } else {
                libdir.parent().unwrap().join("bin").join(name)
            }
        } else {
            link
        };
        let name = runtime.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)));
        let bytes = fs::read(runtime).expect("the linked FIPS module's runtime library");
        if let Some(previous) = libraries.insert(name, bytes.clone()) {
            assert_eq!(previous, bytes, "conflicting native runtime libraries");
        }
    }
    let mut generated = String::from("pub const LIBRARIES: &[(&str, &[u8])] = &[\n");
    for (name, bytes) in libraries {
        // Stage beside both normal binaries and Cargo's integration-test executables. The exact
        // same bytes are embedded for upgrade-safe helper pinning and distribution staging.
        for directory in [profile.to_path_buf(), profile.join("deps"), out.clone()] {
            fs::create_dir_all(&directory).unwrap();
            let temporary = directory.join(format!(".{name}.{}", std::process::id()));
            fs::write(&temporary, &bytes).unwrap();
            fs::rename(temporary, directory.join(&name)).unwrap();
        }
        generated.push_str(&format!(
            "({name:?}, include_bytes!({:?})),\n",
            out.join(&name)
        ));
    }
    generated.push_str("];\n");
    fs::write(out.join("native_runtime.rs"), generated).unwrap();
}
