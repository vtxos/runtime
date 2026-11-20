//! `fake-host-run <component.wasm> [args…]`: run a `wasm32-wasip2` test binary against the fake
//! host, as cargo's runner for the policy's tests (`guests/policy/.cargo/config.toml`).

use std::path::Path;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let mut args = std::env::args().skip(1);
    let wasm = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: fake-host-run <component.wasm> [args…]"))?;
    let rest: Vec<String> = args.collect();
    let code = fake_host::run_command(Path::new(&wasm), &rest).await?;
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
}
