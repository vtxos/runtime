//! The policy, as a Wasm component.
//!
//! One instance serves one wallet: which wallet is configuration, not something a caller names per
//! request — that is what removes the whole class of confusion the old `/u/{group_key}/...` routing
//! had, where a caller could name one wallet while addressing another. There is no other wallet to
//! address.
//!
//! There is no listener here and no transport. The component exports `enclave:rpc/service`: the
//! runtime owns the socket, the TLS, HTTP/2 and gRPC's framing, and calls [`Component::call`] once
//! per call with its messages as a stream. It also exports `run-task`, which the runtime calls on
//! its own schedule. Both are in `enclave_wit`'s `guest` world, read from the runtime's own WIT.
//!
//! Nor is there a shutdown signal. The old server caught SIGTERM so in-flight sessions could
//! finish; a guest has no signals, and the runtime stopping an instance between requests is what
//! the equivalent looks like here.

use std::sync::{Arc, Mutex};

use enclave_wit::exports::enclave::rpc::service as rpc;
use enclave_wit::{wit_future, wit_stream};
use policy::status::{Code, Status};
use policy::wire::{Wire, WireFuture};
use policy::{config, session, store, Policy};
use wit_bindgen::{FutureReader, StreamReader, StreamWriter};

/// What the seal is filed under when `COSIGNER_GROUP_KEY` says nothing — see [`open_policy`].
const DEFAULT_GROUP_KEY: &str = "wallet";

struct Component;

impl rpc::Guest for Component {
    async fn call(
        method: String,
        requests: StreamReader<Vec<u8>>,
    ) -> (StreamReader<Vec<u8>>, FutureReader<Result<(), rpc::Status>>) {
        let (replies, out) = wit_stream::new::<Vec<u8>>();
        let (done, status) = wit_future::new::<Result<(), rpc::Status>>(|| {
            Err(rpc::Status {
                code: Code::Internal as u32,
                message: "the call ended without a status".into(),
            })
        });
        // Returned at once, so the runtime can send the head; the call runs after. The streams are
        // dropped when `serve` returns, so every reply is out before the status is written.
        wit_bindgen::spawn(async move {
            let outcome = serve(&method, Box::new(Streams { requests, replies })).await;
            let _ = done
                .write(outcome.map_err(|s| rpc::Status {
                    code: s.code() as u32,
                    message: s.message().to_string(),
                }))
                .await;
        });
        (out, status)
    }
}

/// `run-task`, the other half of `enclave:tasks/background`.
///
/// The runtime calls this on its own schedule with no request in flight, so it opens the wallet
/// itself rather than sharing one — there is no instance kept between a request and a task to
/// share. When the sealed delegate has come due it runs it against the ASP its settings name —
/// see `Policy::run_task_with` — and wakes the owner only when it cannot.
impl enclave_wit::Guest for Component {
    fn run_task(task_id: String, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        // The runtime records a failed run's error inside the sealed task record, where nobody
        // reads it; stderr reaches the console. Said here too, so a watch that keeps failing
        // says why.
        println!("run-task {task_id}: start");
        let run = || {
            let cfg = config::Config::from_environment();
            let mut wallet = open_policy(&cfg).map_err(|e| e.to_string())?;
            // The ASP, when the settings name one — a due delegate is then run here, not handed
            // back to a phone. A native build (clippy, the fake host's wire types) has no client.
            #[cfg(target_arch = "wasm32")]
            let mut asp = policy::asp::rest::AspRest::from_env();
            #[cfg(not(target_arch = "wasm32"))]
            let mut asp = None::<policy::asp::NoAsp>;
            println!("run-task {task_id}: asp={}", if asp.is_some() { "yes" } else { "no" });
            wstd::runtime::block_on(wallet.run_task_with(&task_id, &payload, asp.as_mut()))
        };
        run()
            .inspect(|_| println!("run-task {task_id}: done"))
            .inspect_err(|e| eprintln!("background task {task_id} failed: {e}"))
    }
}

enclave_wit::export!(Component);

/// The call's two streams, as the router reads and writes them.
struct Streams {
    requests: StreamReader<Vec<u8>>,
    replies: StreamWriter<Vec<u8>>,
}

impl Wire for Streams {
    fn recv(&mut self) -> WireFuture<'_, Option<Vec<u8>>> {
        Box::pin(self.requests.next())
    }

    fn send(&mut self, message: Vec<u8>) -> WireFuture<'_, ()> {
        Box::pin(async move {
            // Handed back only when the runtime has dropped the stream: the client went away, and
            // the next read finds that out.
            let _ = self.replies.write_one(message).await;
        })
    }
}

async fn serve(method: &str, wire: Box<dyn Wire>) -> Result<(), Status> {
    let opened = (|| {
        let cfg = config::Config::from_environment();

        // Refuse to serve with an empty `bitcoin_network`. The client uses this string verbatim as
        // the HRP source for rendering wallet addresses; an empty value would silently fall through
        // to a wrong-network default on the client side. `from_environment` already defaults to
        // "regtest" on a missing var, so this only fires when the operator explicitly set
        // BITCOIN_NETWORK="".
        const VALID_NETWORKS: [&str; 5] = ["mainnet", "testnet", "signet", "mutinynet", "regtest"];
        if !VALID_NETWORKS.contains(&cfg.bitcoin_network.as_str()) {
            return Err(Status::failed_precondition(format!(
                "invalid BITCOIN_NETWORK={:?}; expected one of {VALID_NETWORKS:?}",
                cfg.bitcoin_network
            )));
        }

        let policy = Arc::new(Mutex::new(open_policy(&cfg)?));
        let server_info = policy::wallet_proto::GetServerInfoResponse {
            bitcoin_network: cfg.bitcoin_network.clone(),
        };
        Ok(session::Session::new(policy, server_info))
    })();

    match opened {
        Ok(session) => session.route(method, wire).await,
        // A failure to open the wallet at all is still a call that has to answer. Reporting it as
        // its status rather than failing the call is what lets a client tell "this wallet is
        // misconfigured" from "the runtime could not reach the guest".
        Err(status) => {
            eprintln!("request failed before routing: {status}");
            Err(status)
        }
    }
}

/// This instance's wallet, loaded from its seal.
///
/// Shared by the request path and the background task, which both need the whole wallet and get it
/// the same way: there is no instance kept between them to inherit.
fn open_policy(cfg: &config::Config) -> Result<Policy, Status> {
    // The only thing this instance opens: its own store, a directory on the filesystem the runtime
    // scoped to this client. No ASP connection, no push channel — the caller drives the Ark
    // protocol and the host wakes devices.
    let store = Arc::new(
        store::Store::open(&cfg.store_dir, cfg.auto_settle_safety_margin_secs)
            .map_err(|e| Status::internal(format!("opening the store: {e}")))?,
    );

    // Which wallet this instance serves. Configuration, not something a caller names per request —
    // but it no longer has to be *supplied*, and under a real runtime it cannot be.
    //
    // enclave-runtime scopes each tenant's filesystem before the guest sees it, so the store this
    // instance opened already belongs to exactly one wallet; there is nothing here to route
    // between and this string is only the key the seal is filed under. Requiring it also could not
    // work: nothing the deployment sets names it, so nothing reaches the guest to set it and the
    // instance refused to start at all.
    //
    // Safe to default because it is *not* the wallet's identity: the wallet key is the runtime's,
    // and a restart still finds its snapshot under the same bootstrap name. The env var stays for
    // a deployment that runs several wallets over one filesystem.
    let group_key =
        std::env::var("COSIGNER_GROUP_KEY").unwrap_or_else(|_| DEFAULT_GROUP_KEY.to_string());

    Policy::open(store, group_key)
}

fn main() {}
