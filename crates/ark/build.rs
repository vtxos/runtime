fn main() -> Result<(), Box<dyn std::error::Error>> {
    // arkd's prost message types, under `signing`: the policy guest relays its events and builds its
    // requests from them, and needs no transport of its own.
    #[cfg(feature = "signing")]
    {
        const PROTOS: [&str; 2] = ["proto/ark/v1/service.proto", "proto/ark/v1/indexer.proto"];
        tonic_build::configure()
            .build_client(false)
            .build_server(false)
            .compile_protos(&PROTOS, &["proto"])?;

        // The gRPC client stubs alone, over the messages above, for `tests/live_arkd.rs` to
        // `include!` against a real arkd. Written to a directory of their own and never included by
        // the library, so nothing here reaches the wasm build; tonic is a dev-dependency only.
        let grpc = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("grpc");
        std::fs::create_dir_all(&grpc)?;
        tonic_build::configure()
            .build_client(true)
            .build_server(false)
            .extern_path(".ark.v1", "::ark::client::proto")
            .out_dir(&grpc)
            .compile_protos(&PROTOS, &["proto"])?;
    }
    Ok(())
}
