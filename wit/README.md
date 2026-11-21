# wit

The runtime's interfaces, and the `enclave-wit` crate that carries them to a guest.

| Package | What it is |
|---|---|
| [`enclave:tasks`](tasks/tasks.wit) | Durable background tasks: the queue, and the `run-task` export |
| [`enclave:notify`](notify/notify.wit) | Waking a tenant's devices |
| [`enclave:signer`](signer/signer.wit) | The wallet key the runtime holds, and its signing rounds |
| [`enclave:telemetry`](telemetry/telemetry.wit) | Spans and metrics, attributed to the tenant |
| [`enclave:rpc`](rpc/rpc.wit) | gRPC ended by the runtime: a guest exports `service` and sees only messages |
| [`enclave:guest`](guest/guest.wit) | World `guest`: serves `enclave:rpc`, runs tasks, may import everything above |

## For a guest in Rust

Depend on this directory as a crate: by path inside this repository, by git from anywhere else.

```toml
enclave-wit = { git = "https://github.com/vtxos/runtime", rev = "<commit>" }
```

It generates the `guest` world's bindings: call `enclave_wit::enclave::signer::wallet::wallet_key()` and the rest directly, implement `enclave_wit::exports::enclave::rpc::service::Guest` and `enclave_wit::Guest`, then `enclave_wit::export!(YourType)`. The WIT files are read from this crate's own directory, so a guest keeps no copy.

`examples/guest-http` keeps copies under its `wit/deps/`, checked by `scripts/wit-drift.sh`; it is its own workspace and predates the crate.
