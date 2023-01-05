use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // this is meant to help intellij
    let original_out_dir = PathBuf::from(env::var("OUT_DIR")?);

    tonic_build::configure()
        .file_descriptor_set_path(original_out_dir.join("registry_descriptor.bin"))
        .build_client(false)
        .compile(&["../proto/registry.proto"], &["../proto"])
        .unwrap();
    Ok(())
}
