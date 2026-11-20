//! A small host for `policy.wasm`: the runtime's part, played by fakes, so a test can drive the
//! very component a release ships, and not a native build of its library.
//!
//! It links the component as the runtime does: all of WASI, `wasi:http` outgoing, and the four
//! interfaces the runtime adds (tasks, notify, telemetry, signer). Each call gets a fresh instance
//! over one tenant directory preopened as `/`, so state survives only through what the cosigner
//! seals, as in an enclave. A call is made the way the runtime makes it: through the component's
//! `enclave:rpc/service` export, with the messages as a stream, so the framing a client sees is
//! the runtime's business and not this host's.
//!
//! It also runs the policy's own tests ([`run_command`], the `fake-host-run` binary): a test
//! binary built for `wasm32-wasip2` calls the runtime's interfaces directly, and these fakes answer
//! it, set up and read back through `enclave:fake-host/control`.
//!
//! What it fakes, and how:
//!
//! - **Tasks** are queued, and run when the test asks: [`Host::run_due`] is the runtime's scheduler,
//!   in miniature. Each run is a fresh instance calling the `run-task` export.
//! - **The runtime's rule for background work** is kept: only a request may arm a task, cancel
//!   one or enrol a device. A background run may wake its owner and nothing more,
//!   and here, as in the runtime, anything else it asks for is refused.
//! - **Wakes and devices** are recorded for the test to read.
//! - **The ASP** is answered in process: the component's outgoing HTTP to [`ASP_ORIGIN`] never
//!   leaves the host, and anything else is denied. See [`Asp`].
//! - **Telemetry** is accepted and dropped.
//! - **The wallet key** is a stand-in for the runtime's ([`key`]): [`Runtime::dkg_round1`] and
//!   [`Runtime::dkg_finish`] leave the key a registration would, and `enclave:signer` signs with
//!   it. Requests only, as in the runtime.

pub mod key;

use std::collections::BTreeMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use wasmtime::component::{
    Component, ComponentType, Destination, FutureConsumer, InstancePre, Lift, Linker, Lower,
    Resource, ResourceTable, ResourceType, Source, StreamConsumer, StreamProducer, StreamReader,
    StreamResult,
};
use wasmtime::{Config, Engine, Store, StoreContextMut};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{
    HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig,
};
use wasmtime_wasi_http::p2::{HttpResult, WasiHttpCtxView, WasiHttpHooks, WasiHttpView};
use wasmtime_wasi_http::WasiHttpCtx;

/// Where the component is told its ASP is (`ASP_URL`), and the only origin it can reach.
pub const ASP_ORIGIN: &str = "http://asp.test";

/// One queued task, as the runtime keeps it.
#[derive(Clone, Debug)]
pub struct Task {
    pub payload: Vec<u8>,
    pub run_at_ms: u64,
    pub interval_ms: Option<u64>,
    pub cancelled: bool,
    pub runs: u64,
}

/// What the fakes hold and recorded, shared by every instance.
#[derive(Default)]
pub struct Runtime {
    pub tasks: Mutex<BTreeMap<String, Task>>,
    /// Each task the first time it was armed, in order, as it was armed.
    pub enqueued: Mutex<Vec<(String, Task)>>,
    /// Every cancel asked for, in order, whether or not there was a task to cancel.
    pub cancelled: Mutex<Vec<String>>,
    pub devices: Mutex<Vec<String>>,
    pub wakes: Mutex<Vec<(String, Option<String>)>>,
    pub asp: Mutex<Asp>,
    /// The tenant's wallet key, once [`Runtime::dkg_finish`] has kept one.
    pub key: Mutex<Option<key::WalletKey>>,
    /// The cosigner's half of a DKG between its two calls.
    pending: Mutex<Option<key::Pending>>,
}

const NOT_INTERACTIVE: &str = "only a request may do this; a background run may only wake";

impl Runtime {
    fn enqueue(&self, interactive: bool, id: String, payload: Vec<u8>, run_at_ms: u64, interval_ms: Option<u64>) -> Result<(), String> {
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        let mut tasks = self.tasks.lock().unwrap();
        if let Some(old) = tasks.get(&id) {
            // An id is an idempotency key: the same input again is a no-op, and different input is
            // refused until the old record is cancelled and forgotten.
            if old.payload != payload || old.run_at_ms != run_at_ms || old.interval_ms != interval_ms {
                return Err("task id already used with different input".into());
            }
            return Ok(());
        }
        let task = Task { payload, run_at_ms, interval_ms, cancelled: false, runs: 0 };
        self.enqueued.lock().unwrap().push((id.clone(), task.clone()));
        tasks.insert(id, task);
        Ok(())
    }

    fn cancel(&self, interactive: bool, id: &str) -> Result<(), String> {
        self.cancelled.lock().unwrap().push(id.to_string());
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        match self.tasks.lock().unwrap().get_mut(id) {
            Some(task) => {
                task.cancelled = true;
                Ok(())
            }
            None => Err("no such task".into()),
        }
    }

    fn forget(&self, interactive: bool, id: &str) -> Result<(), String> {
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        let mut tasks = self.tasks.lock().unwrap();
        match tasks.get(id) {
            Some(task) if task.cancelled => {
                tasks.remove(id);
                Ok(())
            }
            Some(_) => Err("task is still active".into()),
            None => Err("no such task".into()),
        }
    }

    fn register_device(&self, interactive: bool, token: String) -> Result<(), String> {
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        if !(32..=512).contains(&token.len()) {
            return Err("a device token is 32 to 512 characters".into());
        }
        let mut devices = self.devices.lock().unwrap();
        if !devices.contains(&token) {
            devices.push(token);
        }
        Ok(())
    }

    fn forget_device(&self, interactive: bool, token: &str) -> Result<(), String> {
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        self.devices.lock().unwrap().retain(|held| held != token);
        Ok(())
    }

    /// DKG round one, the cosigner's half: its round one and the share it deals the wallet.
    pub fn dkg_round1(&self, wallet: &threshold::dkg::Round1Package) -> Result<key::Round1, String> {
        let (reply, pending) = key::round1(wallet)?;
        *self.pending.lock().unwrap() = Some(pending);
        Ok(reply)
    }

    /// DKG round two: the wallet's share in, the key made and kept. Its group key back.
    pub fn dkg_finish(
        &self,
        wallet: &threshold::dkg::Round1Package,
        from_wallet: &threshold::dkg::Round2Package,
    ) -> Result<[u8; 33], String> {
        let pending = self.pending.lock().unwrap().take().ok_or("no round one to finish")?;
        let key = key::finish(pending, wallet, from_wallet)?;
        let group_key = key.group_key();
        *self.key.lock().unwrap() = Some(key);
        Ok(group_key)
    }

    /// Hold [key] from now on, as a DKG leaves the runtime: a key a test dealt itself.
    pub fn hold(&self, key: key::WalletKey) {
        *self.key.lock().unwrap() = Some(key);
    }

    /// Back to a tenant that never registered: no key, no tasks, no devices, nothing recorded.
    pub fn reset(&self) {
        self.tasks.lock().unwrap().clear();
        self.enqueued.lock().unwrap().clear();
        self.cancelled.lock().unwrap().clear();
        self.devices.lock().unwrap().clear();
        self.wakes.lock().unwrap().clear();
        *self.key.lock().unwrap() = None;
        *self.pending.lock().unwrap() = None;
    }

    fn wallet_key(&self, interactive: bool) -> Result<key::WalletKey, String> {
        if !interactive {
            return Err(NOT_INTERACTIVE.into());
        }
        self.key.lock().unwrap().clone().ok_or_else(|| "this tenant has no wallet key yet".into())
    }

    pub fn tasks(&self) -> BTreeMap<String, Task> {
        self.tasks.lock().unwrap().clone()
    }

    pub fn devices(&self) -> Vec<String> {
        self.devices.lock().unwrap().clone()
    }

    pub fn wakes(&self) -> Vec<(String, Option<String>)> {
        self.wakes.lock().unwrap().clone()
    }
}

/// The ASP, in process: the REST calls the component makes, answered from what a test sets here,
/// and every call recorded.
#[derive(Default)]
pub struct Asp {
    /// `GET /v1/info`: the gateway's JSON for the ASP's parameters.
    pub info: serde_json::Value,
    /// Refuse `registerIntent`, as an ASP does that will not take the intent.
    pub refuse_registration: bool,
    /// What `GET /v1/batch/events` streams, each as one server-sent event: the gateway's JSON for
    /// one `GetEventStreamResponse`. The stream ends after the last.
    pub events: Vec<serde_json::Value>,
    /// `(method and path, body)` of every call, in order.
    pub calls: Vec<(String, String)>,
    registrations: u32,
}

impl Asp {
    fn answer(&mut self, method: &str, path: &str, body: &[u8]) -> (u16, &'static str, Bytes) {
        self.calls.push((format!("{method} {path}"), String::from_utf8_lossy(body).into()));
        let json = |v: serde_json::Value| (200, "application/json", Bytes::from(v.to_string()));
        match (method, path) {
            ("GET", "/v1/info") => json(self.info.clone()),
            ("POST", "/v1/batch/registerIntent") if self.refuse_registration => {
                (400, "application/json", Bytes::from(r#"{"message":"refused"}"#))
            }
            ("POST", "/v1/batch/registerIntent") => {
                self.registrations += 1;
                json(serde_json::json!({ "intentId": format!("intent-{}", self.registrations) }))
            }
            ("GET", "/v1/batch/events") => {
                let stream: String =
                    self.events.iter().map(|e| format!("data: {e}\n\n")).collect();
                (200, "text/event-stream", Bytes::from(stream))
            }
            ("POST", "/v1/batch/ack")
            | ("POST", "/v1/batch/tree/submitNonces")
            | ("POST", "/v1/batch/tree/submitSignatures")
            | ("POST", "/v1/batch/submitForfeitTxs") => json(serde_json::json!({})),
            _ => (404, "text/plain", Bytes::from("no such endpoint")),
        }
    }

    /// The calls made, as `method path`.
    pub fn called(&self) -> Vec<String> {
        self.calls.iter().map(|(call, _)| call.clone()).collect()
    }
}

/// One instance's state: WASI over the tenant directory, `wasi:http`, and the fakes.
pub struct State {
    wasi: WasiCtx,
    table: ResourceTable,
    http: WasiHttpCtx,
    hooks: Egress,
    runtime: Arc<Runtime>,
    /// A request (true) or a background run (false). See the module's notes.
    interactive: bool,
}

impl State {
    fn new(wasi: WasiCtx, runtime: Arc<Runtime>, interactive: bool) -> Self {
        State {
            wasi,
            table: ResourceTable::new(),
            http: WasiHttpCtx::new(),
            hooks: Egress(runtime.clone()),
            runtime,
            interactive,
        }
    }
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView { ctx: &mut self.wasi, table: &mut self.table }
    }
}

impl WasiHttpView for State {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView { ctx: &mut self.http, table: &mut self.table, hooks: &mut self.hooks }
    }
}

/// The component's outgoing HTTP: [`ASP_ORIGIN`] is answered by the fake ASP, and anything else
/// is denied, as an origin the image does not allow would be.
struct Egress(Arc<Runtime>);

impl WasiHttpHooks for Egress {
    fn send_request(
        &mut self,
        request: hyper::Request<HyperOutgoingBody>,
        _config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        if request.uri().authority().map(|a| a.as_str()) != ASP_ORIGIN.strip_prefix("http://") {
            return Err(ErrorCode::HttpRequestDenied.into());
        }
        let runtime = self.0.clone();
        let handle = wasmtime_wasi::runtime::spawn(async move {
            let (parts, body) = request.into_parts();
            let body = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => return Ok(Err(e)),
            };
            let (status, content_type, reply) = runtime.asp.lock().unwrap().answer(
                parts.method.as_str(),
                parts.uri.path(),
                &body,
            );
            let resp = hyper::Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(Full::new(reply).map_err(|never| match never {}).boxed_unsync())
                .expect("a well-formed response");
            Ok(Ok(IncomingResponse {
                resp,
                worker: None,
                between_bytes_timeout: Duration::from_secs(30),
            }))
        });
        Ok(HostFutureIncomingResponse::pending(handle))
    }
}

/// The component's `enclave:rpc/service`, as the runtime calls it.
mod rpc {
    wasmtime::component::bindgen!({ path: "../../wit/rpc", world: "enclave:rpc/server" });
}

/// `enclave:fake-host/control`, which a test inside this host sets its fakes up through.
mod control {
    wasmtime::component::bindgen!({ path: "../../wit/fake-host", world: "enclave:fake-host/tester" });
}

use control::enclave::fake_host::control as ctl;
use rpc::exports::enclave::rpc::service::Status;

/// An engine as the runtime configures one: async exports, streams and futures on.
fn engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model_async(true);
    Ok(Engine::new(&config)?)
}

/// The host: one component, one tenant, and the fakes it runs against.
pub struct Host {
    engine: Engine,
    pre: InstancePre<State>,
    server: rpc::ServerPre<State>,
    dir: tempfile::TempDir,
    settings: Vec<(String, String)>,
    pub runtime: Arc<Runtime>,
}

impl Host {
    /// Load [wasm], deployed with [settings]: the guest's environment, as the runtime gives a
    /// guest the settings measured with it. `ASP_URL` is [`ASP_ORIGIN`] unless [settings] say.
    pub fn new(wasm: &Path, settings: &[(&str, &str)]) -> Result<Self> {
        let engine = engine()?;
        let component = Component::from_file(&engine, wasm)
            .map_err(|e| anyhow!("loading {}: {e}", wasm.display()))?;
        let linker = linker(&engine)?;
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|e| anyhow!("linking the component: {e}"))?;
        let server = rpc::ServerPre::new(pre.clone())
            .map_err(|e| anyhow!("the component exports no enclave:rpc/service: {e}"))?;
        let mut settings: Vec<(String, String)> =
            settings.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        if !settings.iter().any(|(k, _)| k == "ASP_URL") {
            settings.push(("ASP_URL".into(), ASP_ORIGIN.into()));
        }
        Ok(Self {
            engine,
            pre,
            server,
            dir: tempfile::tempdir()?,
            settings,
            runtime: Arc::default(),
        })
    }

    fn store(&self, interactive: bool) -> Result<Store<State>> {
        let mut wasi = WasiCtxBuilder::new();
        wasi.preopened_dir(self.dir.path(), "/", DirPerms::all(), FilePerms::all())?;
        wasi.envs(&self.settings);
        // The guest's own logs, in the test's output.
        wasi.inherit_stdout().inherit_stderr();
        Ok(Store::new(&self.engine, State::new(wasi.build(), self.runtime.clone(), interactive)))
    }

    /// Open the call [method] of `cosigner.v1.Cosigner`, on a fresh instance.
    pub async fn call(&self, method: &str) -> Result<Call> {
        let mut store = self.store(true)?;
        let guest = self.server.instantiate_async(&mut store).await?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (replies_tx, replies_rx) = tokio::sync::mpsc::unbounded_channel();
        let (status_tx, status_rx) = tokio::sync::oneshot::channel();
        let path = format!("/cosigner.v1.Cosigner/{method}");
        // The store's event loop is what moves the streams, so it runs for the whole call.
        let task = tokio::spawn(async move {
            store
                .run_concurrent(async move |a| -> wasmtime::Result<()> {
                    let requests = a.with(|mut s| StreamReader::new(&mut s, Requests(rx)))?;
                    let (replies, outcome) =
                        guest.enclave_rpc_service().call_call(a, path, requests).await?;
                    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                    a.with(|mut s| -> wasmtime::Result<()> {
                        replies.pipe(&mut s, Replies(replies_tx))?;
                        outcome.pipe(&mut s, Outcome(Some(done_tx)))?;
                        Ok(())
                    })?;
                    if let Ok(outcome) = done_rx.await {
                        let _ = status_tx.send(outcome);
                    }
                    Ok(())
                })
                .await?
        });
        Ok(Call { tx: Some(tx), replies: replies_rx, status: Some(status_rx), _guest: task })
    }

    /// A unary call: one message in, one out.
    pub async fn unary<Req: prost::Message, Resp: prost::Message + Default>(
        &self,
        method: &str,
        request: &Req,
    ) -> Result<Resp> {
        let mut call = self.call(method).await?;
        call.send(request);
        call.close();
        let response = call.next().await?;
        let (status, message) = call.finish().await?;
        if status != "0" {
            bail!("{method} ended {status}: {message}");
        }
        Ok(response)
    }

    /// The `run-task` export, as the runtime calls it: a fresh instance, in the background.
    pub async fn run_task(&self, run_id: &str, payload: &[u8]) -> Result<Result<Vec<u8>, String>> {
        let mut store = self.store(false)?;
        let instance = self.pre.instantiate_async(&mut store).await?;
        let run = instance.get_typed_func::<(String, Vec<u8>), (Result<Vec<u8>, String>,)>(
            &mut store, "run-task",
        )?;
        let (result,) = run.call_async(&mut store, (run_id.to_string(), payload.to_vec())).await?;
        Ok(result)
    }

    /// The scheduler: run every live task due by [now_ms], each in its own background run, and
    /// move a repeating one on by its interval. Returns `(task id, what the run returned)`.
    pub async fn run_due(&self, now_ms: u64) -> Result<Vec<(String, Result<Vec<u8>, String>)>> {
        let due: Vec<(String, Task)> = self
            .runtime
            .tasks
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t)| !t.cancelled && t.run_at_ms <= now_ms)
            .map(|(id, t)| (id.clone(), t.clone()))
            .collect();
        let mut ran = Vec::new();
        for (id, task) in due {
            // `<id>:<generation>:<occurrence>`, the form the runtime gives `run-task`.
            let run_id = format!("{id}:{}:{}", "0".repeat(32), task.runs);
            let result = self.run_task(&run_id, &task.payload).await?;
            if let Some(task) = self.runtime.tasks.lock().unwrap().get_mut(&id) {
                task.runs += 1;
                match task.interval_ms {
                    Some(interval) => task.run_at_ms = now_ms + interval,
                    None => task.cancelled = true,
                }
            }
            ran.push((id, result));
        }
        Ok(ran)
    }
}

/// The client's end of one call.
pub struct Call {
    tx: Option<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>,
    replies: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    status: Option<tokio::sync::oneshot::Receiver<Result<(), Status>>>,
    _guest: tokio::task::JoinHandle<wasmtime::Result<()>>,
}

impl Call {
    /// Send one message.
    pub fn send<M: prost::Message>(&self, message: &M) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(message.encode_to_vec());
        }
    }

    /// End the client's side: it has nothing more to say.
    pub fn close(&mut self) {
        self.tx = None;
    }

    /// The guest's next message. Its status instead is an error carrying it.
    pub async fn next<M: prost::Message + Default>(&mut self) -> Result<M> {
        let next = tokio::time::timeout(Duration::from_secs(60), self.replies.recv())
            .await
            .context("the guest said nothing for a minute")?;
        match next {
            Some(message) => Ok(M::decode(message.as_slice())?),
            None => {
                let (status, message) = self.status().await?;
                bail!("the stream ended instead: {status}: {message}")
            }
        }
    }

    /// How the call ended: its status code and message, as `grpc-status` and `grpc-message`
    /// would carry them.
    pub async fn finish(mut self) -> Result<(String, String)> {
        self.close();
        // Whatever was still coming is skipped, as a client reading for trailers would.
        while tokio::time::timeout(Duration::from_secs(60), self.replies.recv())
            .await
            .context("the guest said nothing for a minute")?
            .is_some()
        {}
        self.status().await
    }

    async fn status(&mut self) -> Result<(String, String)> {
        let status = self.status.take().ok_or_else(|| anyhow!("the status was already read"))?;
        let outcome = tokio::time::timeout(Duration::from_secs(60), status)
            .await
            .context("the guest gave no status for a minute")?
            .map_err(|_| anyhow!("the guest ended the call without a status"))?;
        Ok(match outcome {
            Ok(()) => ("0".into(), String::new()),
            Err(s) => (s.code.to_string(), s.message),
        })
    }
}

/// The client's messages, as the guest's request stream: nothing yet is `Pending`, as on a live
/// connection, and a closed sender is the client's half-close.
struct Requests(tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>);

impl<D> StreamProducer<D> for Requests {
    type Item = Vec<u8>;
    type Buffer = Option<Vec<u8>>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Vec<u8>, Option<Vec<u8>>>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        match self.0.poll_recv(cx) {
            Poll::Ready(Some(message)) => {
                destination.set_buffer(Some(message));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => Poll::Ready(Ok(StreamResult::Dropped)),
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The guest's replies, handed to the test as they come.
struct Replies(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

impl<D> StreamConsumer<D> for Replies {
    type Item = Vec<u8>;

    fn poll_consume(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, Vec<u8>>,
        _: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        let mut one = None;
        source.read(&mut store, &mut one)?;
        let gone = one.is_some_and(|message| self.0.send(message).is_err());
        Poll::Ready(Ok(if gone { StreamResult::Dropped } else { StreamResult::Completed }))
    }
}

/// The guest's status, once it writes one.
struct Outcome(Option<tokio::sync::oneshot::Sender<Result<(), Status>>>);

impl<D> FutureConsumer<D> for Outcome {
    type Item = Result<(), Status>;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        mut store: StoreContextMut<D>,
        mut source: Source<'_, Self::Item>,
        _: bool,
    ) -> Poll<wasmtime::Result<()>> {
        let mut value = None;
        source.read(&mut store, &mut value)?;
        if let (Some(tx), Some(value)) = (self.0.take(), value) {
            let _ = tx.send(value);
        }
        Poll::Ready(Ok(()))
    }
}

/// Run [wasm], a `wasi:cli` command such as a test binary built for `wasm32-wasip2`, with [args],
/// against these fakes. What `fake-host-run` is: cargo's runner for the policy's tests.
///
/// The command sees this process's stdio and environment, and a fresh temporary directory as
/// `/tmp` (`TMPDIR`). Returns the command's exit code.
pub async fn run_command(wasm: &Path, args: &[String]) -> Result<i32> {
    let engine = engine()?;
    let component = Component::from_file(&engine, wasm)
        .map_err(|e| anyhow!("loading {}: {e}", wasm.display()))?;
    let mut linker = linker(&engine)?;
    control::Tester::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
        &mut linker,
        |s| s,
    )?;

    let tmp = tempfile::tempdir()?;
    let mut wasi = WasiCtxBuilder::new();
    let name = wasm.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    wasi.arg(name).args(args);
    wasi.inherit_stdio().inherit_env().env("TMPDIR", "/tmp");
    wasi.preopened_dir(tmp.path(), "/tmp", DirPerms::all(), FilePerms::all())?;
    let mut store =
        Store::new(&engine, State::new(wasi.build(), Arc::new(Runtime::default()), true));

    let command =
        wasmtime_wasi::p2::bindings::Command::instantiate_async(&mut store, &component, &linker)
            .await
            .map_err(|e| anyhow!("instantiating {}: {e}", wasm.display()))?;
    match command.wasi_cli_run().call_run(&mut store).await {
        Ok(Ok(())) => Ok(0),
        Ok(Err(())) => Ok(1),
        // `std::process::exit`, which is how a failing test binary ends.
        Err(e) => match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(exit) => Ok(exit.0),
            None => Err(e.into()),
        },
    }
}

impl ctl::Host for State {
    fn hold(
        &mut self,
        key_package: String,
        public_key_package: String,
        wallet_identifier: Vec<u8>,
        dealt: Vec<u8>,
    ) {
        let identifier: [u8; 32] =
            wallet_identifier.try_into().expect("a wallet identifier is 32 bytes");
        self.runtime.hold(key::WalletKey {
            key_package: threshold::keys::KeyPackage::from_json(&key_package)
                .expect("threshold's key package JSON"),
            public_key_package: threshold::keys::PublicKeyPackage::from_json(&public_key_package)
                .expect("threshold's public key package JSON"),
            wallet: threshold::identifier::Identifier::deserialize(&identifier)
                .expect("a wallet identifier"),
            dealt,
        });
    }

    fn reset(&mut self) {
        self.runtime.reset();
    }

    fn enqueued(&mut self) -> Vec<ctl::Task> {
        self.runtime
            .enqueued
            .lock()
            .unwrap()
            .iter()
            .map(|(id, task)| ctl::Task {
                id: id.clone(),
                payload: task.payload.clone(),
                run_at: task.run_at_ms,
                interval_ms: task.interval_ms,
            })
            .collect()
    }

    fn woken(&mut self) -> Vec<(String, Option<String>)> {
        self.runtime.wakes()
    }

    fn cancelled(&mut self) -> Vec<String> {
        self.runtime.cancelled.lock().unwrap().clone()
    }
}

// --- The runtime's interfaces ------------------------------------------------------------------
//
// The telemetry types only describe the ABI, so a call can be lifted; the fakes read none of it.

#[allow(dead_code)]
#[derive(ComponentType, Lift, Clone, Copy)]
#[component(enum)]
#[repr(u8)]
enum Level {
    #[component(name = "trace")]
    Trace,
    #[component(name = "debug")]
    Debug,
    #[component(name = "info")]
    Info,
    #[component(name = "warn")]
    Warn,
    #[component(name = "error")]
    Error,
}

#[allow(dead_code)]
#[derive(ComponentType, Lift, Clone)]
#[component(record)]
struct Field {
    #[component(name = "key")]
    key: String,
    #[component(name = "value")]
    value: String,
}

#[allow(dead_code)]
#[derive(ComponentType, Lift, Clone, Copy)]
#[component(enum)]
#[repr(u8)]
enum Unit {
    #[component(name = "none")]
    None,
    #[component(name = "count")]
    Count,
    #[component(name = "seconds")]
    Seconds,
    #[component(name = "milliseconds")]
    Milliseconds,
    #[component(name = "bytes")]
    Bytes,
    #[component(name = "kilobytes")]
    Kilobytes,
    #[component(name = "percent")]
    Percent,
}

#[allow(dead_code)]
#[derive(ComponentType, Lift, Clone)]
#[component(record)]
struct Dimension {
    #[component(name = "name")]
    name: String,
    #[component(name = "value")]
    value: String,
}

struct Span;

/// `enclave:signer`'s `signing`: a round, until `finish` spends it.
struct Signing(Option<key::Signing>);

#[derive(ComponentType, Lower, Clone)]
#[component(record)]
struct Commitment {
    #[component(name = "hiding")]
    hiding: Vec<u8>,
    #[component(name = "binding")]
    binding: Vec<u8>,
}

#[derive(ComponentType, Lift, Clone)]
#[component(record)]
struct WalletRound {
    #[component(name = "hiding")]
    hiding: Vec<u8>,
    #[component(name = "binding")]
    binding: Vec<u8>,
    #[component(name = "share")]
    share: Vec<u8>,
}

#[derive(ComponentType, Lower, Clone)]
#[component(record)]
struct WalletKey {
    #[component(name = "group-key")]
    group_key: Vec<u8>,
    #[component(name = "public-key-package")]
    public_key_package: String,
    #[component(name = "signer-identifier")]
    signer_identifier: Vec<u8>,
    #[component(name = "wallet-identifier")]
    wallet_identifier: Vec<u8>,
}

fn linker(engine: &Engine) -> Result<Linker<State>> {
    let mut linker = Linker::new(engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
    wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;

    let mut queue = linker.instance("enclave:tasks/queue@0.1.0")?;
    queue.func_wrap(
        "enqueue",
        |store, (id, payload, at, interval): (String, Vec<u8>, u64, Option<u64>)| {
            let s: &State = store.data();
            Ok((s.runtime.enqueue(s.interactive, id, payload, at, interval),))
        },
    )?;
    queue.func_wrap("status", |store, (id,): (String,)| {
        let s: &State = store.data();
        let tasks = s.runtime.tasks.lock().unwrap();
        Ok((tasks
            .get(&id)
            .map(|t| serde_json::json!({ "cancelled": t.cancelled, "runs": t.runs }).to_string())
            .ok_or_else(|| "no such task".to_string()),))
    })?;
    queue.func_wrap("cancel", |store, (id,): (String,)| {
        let s: &State = store.data();
        Ok((s.runtime.cancel(s.interactive, &id),))
    })?;
    queue.func_wrap("forget", |store, (id,): (String,)| {
        let s: &State = store.data();
        Ok((s.runtime.forget(s.interactive, &id),))
    })?;

    let mut notify = linker.instance("enclave:notify/notify@0.1.0")?;
    notify.func_wrap("register-device", |store, (token,): (String,)| {
        let s: &State = store.data();
        Ok((s.runtime.register_device(s.interactive, token),))
    })?;
    notify.func_wrap("forget-device", |store, (token,): (String,)| {
        let s: &State = store.data();
        Ok((s.runtime.forget_device(s.interactive, &token),))
    })?;
    notify.func_wrap("devices", |store, (): ()| {
        let s: &State = store.data();
        Ok((Ok::<u32, String>(s.runtime.devices.lock().unwrap().len() as u32),))
    })?;
    notify.func_wrap(
        "wake",
        |store, (category, reference): (String, Option<String>)| {
            let s: &State = store.data();
            s.runtime.wakes.lock().unwrap().push((category, reference));
            Ok((Ok::<(), String>(()),))
        },
    )?;

    let mut tracing = linker.instance("enclave:telemetry/tracing@0.1.0")?;
    tracing.resource("span", ResourceType::host::<Span>(), |mut store, rep| {
        store.data_mut().table.delete(Resource::<Span>::new_own(rep))?;
        Ok(())
    })?;
    tracing.func_wrap("event", |_, (_, _, _): (Level, String, Vec<Field>)| Ok(()))?;
    tracing.func_wrap("[constructor]span", |mut store, (_, _, _): (Level, String, Vec<Field>)| {
        Ok((store.data_mut().table.push(Span)?,))
    })?;
    tracing.func_wrap("[method]span.set-field", |_, (_, _, _): (Resource<Span>, String, String)| {
        Ok(())
    })?;
    tracing.func_wrap(
        "[method]span.add-event",
        |_, (_, _, _, _): (Resource<Span>, Level, String, Vec<Field>)| Ok(()),
    )?;
    tracing.func_wrap("[method]span.end", |_, (_,): (Resource<Span>,)| Ok(()))?;

    let mut wallet = linker.instance("enclave:signer/wallet@0.1.0")?;
    wallet.resource("signing", ResourceType::host::<Signing>(), |mut store, rep| {
        store.data_mut().table.delete(Resource::<Signing>::new_own(rep))?;
        Ok(())
    })?;
    wallet.func_wrap("wallet-key", |store, (): ()| {
        let s: &State = store.data();
        Ok((s.runtime.wallet_key(s.interactive).map(|key| WalletKey {
            group_key: key.group_key().to_vec(),
            public_key_package: key.public_key_package.to_json(),
            signer_identifier: key.cosigner().serialize().to_vec(),
            wallet_identifier: key.wallet.serialize().to_vec(),
        }),))
    })?;
    wallet.func_wrap("dealt-share", |store, (identifier,): (Vec<u8>,)| {
        let s: &State = store.data();
        Ok((s.runtime.wallet_key(s.interactive).and_then(|key| {
            if identifier != key.wallet.serialize() {
                return Err("not this wallet's identifier".to_string());
            }
            Ok(key.dealt)
        }),))
    })?;
    wallet.func_wrap("[static]signing.begin", |mut store, (messages,): (Vec<Vec<u8>>,)| {
        let s: &State = store.data();
        let key = match s.runtime.wallet_key(s.interactive) {
            Ok(key) => key,
            Err(e) => return Ok((Err(e),)),
        };
        let (signing, commitments) = key::Signing::begin(&key, &messages);
        let handle = store.data_mut().table.push(Signing(Some(signing)))?;
        let commitments: Vec<_> = commitments
            .into_iter()
            .map(|(hiding, binding)| Commitment { hiding: hiding.to_vec(), binding: binding.to_vec() })
            .collect();
        Ok((Ok((handle, commitments)),))
    })?;
    wallet.func_wrap(
        "[method]signing.finish",
        |mut store, (handle, rounds): (Resource<Signing>, Vec<WalletRound>)| {
            let result = match store.data_mut().table.get_mut(&handle)?.0.take() {
                None => Err("this round is already finished".to_string()),
                Some(signing) => {
                    let rounds: Vec<_> =
                        rounds.into_iter().map(|r| (r.hiding, r.binding, r.share)).collect();
                    signing.finish(&rounds)
                }
            };
            Ok((result,))
        },
    )?;

    let mut metrics = linker.instance("enclave:telemetry/metrics@0.1.0")?;
    metrics.func_wrap("counter-add", |_, (_, _, _): (String, f64, Vec<Dimension>)| Ok(()))?;
    for name in ["gauge-set", "histogram-record"] {
        metrics.func_wrap(name, |_, (_, _, _, _): (String, f64, Unit, Vec<Dimension>)| Ok(()))?;
    }

    Ok(linker)
}
