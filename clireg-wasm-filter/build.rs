fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_client(false)
        .build_server(false)
        .compile(&["../proto/registry.proto"], &["../proto"])
        .unwrap();
    Ok(())
}
