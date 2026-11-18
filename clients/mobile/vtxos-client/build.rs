fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The policy guest's wire, client stubs only, from the protos every client generates from.
    // `cosign_session.proto` imports `mpc_wallet.proto`'s shapes; `extern_path` points them at the
    // module generated first instead of generating them twice.
    let wire = "../../../protocol/protos";
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&[format!("{wire}/mpc_wallet.proto")], &[wire])?;
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .build_transport(false)
        .extern_path(".mpc_wallet", "crate::proto::wallet")
        .compile_protos(&[format!("{wire}/cosign_session.proto")], &[wire])?;

    // arkd's two services, client stubs only, over the messages `crates/ark` already generates: the
    // guest consumes those types, so the events relayed to it are the same Rust values.
    let arkd = "../../../crates/ark/proto";
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("arkd");
    std::fs::create_dir_all(&out)?;
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .build_transport(false)
        .extern_path(".ark.v1", "::ark::client::proto")
        .out_dir(&out)
        .compile_protos(
            &[
                format!("{arkd}/ark/v1/service.proto"),
                format!("{arkd}/ark/v1/indexer.proto"),
            ],
            &[arkd],
        )?;
    Ok(())
}
