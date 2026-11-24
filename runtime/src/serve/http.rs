//! Dispatching an incoming HTTP request into the guest: a `wasi:http/proxy` guest as HTTP, or an
//! `enclave:rpc/service` guest as gRPC ended here (see [`crate::serve::grpc`]).
//!
//! **One instance per request. No two requests ever share one.**
//!
//! That is the invariant this module exists to hold, and it is where the
//! boundary between two clients actually lives. A `Store` is what separates two
//! wasm instances; give two clients one instance and the separation becomes
//! guest code instead, so a single bug that confuses two clients stops being a
//! leak of one and becomes a total compromise. A trap has nothing to poison and
//! leaked resource handles die with the store, both for the same reason.
//!
//! What a guest keeps therefore has to reach the filesystem, because there is
//! nothing else: no memory outlives the call that created it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use wasmtime::component::{Component, InstancePre, Resource};
use wasmtime::{Engine, Store, UpdateDeadline};
use wasmtime_wasi_http::io::TokioIo;
use wasmtime_wasi_http::p2::bindings::http::types::Scheme;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;
use wasmtime_wasi_http::p2::types::{HostIncomingRequest, HostResponseOutparam};
use wasmtime_wasi_http::p2::WasiHttpView;

use crate::auth::{AuthEndpoints, Gate};
use crate::linker::build_linker;
use crate::run::GuestEnvironment;
use crate::serve::attest::{nonce_from_headers, ResponseAttestor};
use crate::serve::client::apply_tenant;
use crate::serve::grpc;
use crate::serve::pool::{PoolLimits, TenantPool};
use crate::serve::progress::{Counting, StreamProgress};
use crate::serve::tls::TlsIdentity;
use crate::state::State;
use nitro_nsm::Nsm;

/// How the guest is served.
#[derive(Debug)]
pub struct ServeConfig {
    /// Tenant-bound durable tasks, which run when the guest exports `run-task`: their limits,
    /// and where they are scheduled. `None` turns them off whatever the guest exports.
    pub background_tasks: Option<crate::tasks::BackgroundTasks>,
    /// Opt-in push notifications. The registry and the forwarder are opened
    /// here rather than by the caller, because both need the mounted
    /// filesystem and the trusted clock, and this is where those exist.
    pub notify: Option<crate::notify::NotifyConfig>,
    /// Where guest spans and metrics go. The default sends nowhere, and the guest's calls still
    /// succeed — see [`crate::telemetry`].
    pub telemetry: crate::telemetry::Telemetry,
    /// Address to accept on.
    pub addr: SocketAddr,
    /// The certificate every TLS connection is served: one the enclave made for
    /// itself at boot. `None` serves plaintext.
    pub certificate: Option<Arc<TlsIdentity>>,
    /// NSM to sign the attestation document on each `/auth/*` response.
    ///
    /// Only useful alongside `tls`: the document binds the serving
    /// certificate, and without one there is nothing to bind. Supplying it
    /// without TLS is refused rather than silently serving documents that
    /// promise a binding they do not have.
    pub attestation: Option<Arc<dyn Nsm>>,
    /// How long a guest may take to produce a response head.
    ///
    /// A guest that neither returns nor sets a response otherwise hangs that
    /// tenant forever — and only that tenant, since nothing else queues behind
    /// it. See [`EPOCH_TICK`].
    pub request_timeout: Duration,
    /// How long an interaction may run once it has answered.
    ///
    /// Deliberately separate from `request_timeout`: that one bounds getting a
    /// head out, and does not apply afterwards, so without this a stream had no
    /// ceiling at all and held its tenant's slot indefinitely.
    pub max_interaction: Duration,
    /// Give each authenticated client their own filesystem. `None` keeps the
    /// original model: one filesystem, a fresh instance per request.
    pub tenancy: Option<Arc<Tenancy>>,
    /// `/auth/*` and the gate every other request must pass.
    ///
    /// `None` serves the guest to anyone who can open a connection. That is a
    /// development and QEMU arrangement, and [`serve_component`] says so
    /// loudly at startup rather than leaving it to be noticed.
    pub authentication: Option<(Arc<AuthEndpoints>, Arc<Gate>)>,
}

impl Default for ServeConfig {
    /// One request at a time.
    ///
    /// The store layer is safe to share — `Fs` keeps its handles under a
    /// `parking_lot::Mutex` and its transaction state under a `tokio::Mutex`,
    /// so nothing corrupts. The *guest* is the problem. `docs/COMPATIBILITY.md`
    /// records that SQLite on WASI has to run `locking_mode=EXCLUSIVE`, because
    /// WASI has no `fcntl` and therefore no file locking; two guest instances
    /// holding the same database would each believe they had it alone.
    ///
    /// A guest that keeps no cross-request state in the filesystem can raise
    /// this safely. One that opens a database cannot, and would fail in a way
    /// that looks like corruption rather than contention — so the default is
    /// the one that cannot surprise anybody.
    fn default() -> Self {
        ServeConfig {
            background_tasks: None,
            notify: None,
            telemetry: Default::default(),
            addr: ([0, 0, 0, 0], 8080).into(),
            certificate: None,
            attestation: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_interaction: DEFAULT_MAX_INTERACTION,
            // Off. Turning it on changes what two clients may do at the same
            // time, which a guest may have been relying on — so it is asked
            // for, never inherited.
            tenancy: None,
            authentication: None,
        }
    }
}

/// How often the epoch advances, and therefore the resolution of the deadline
/// a spinning guest is trapped by.
///
/// Coarse on purpose: the ticker wakes on every interval for the life of the
/// process, and the deadline only needs to be accurate to a fraction of the
/// request timeout.
const EPOCH_TICK: Duration = Duration::from_millis(250);

/// Consecutive silent epoch expiries before a call is judged a runaway.
///
/// This — not `request_timeout` — is what bounds how long a guest can burn a
/// worker after its budget is spent, and it is deliberately independent of the
/// budget: a deployment that allows generous head timeouts should not thereby
/// allow generous spinning. Eight ticks is two seconds, long enough that a
/// loaded machine delivering frames late is never mistaken for one delivering
/// nothing, short enough that a genuine runaway is gone before it matters.
const SILENT_TICKS_BEFORE_TRAP: u32 = 8;

/// Default ceiling on producing a response head.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a client has to finish the TLS handshake. Nothing else bounds a
/// connection before its first request, so without this a peer that opens
/// connections and says nothing holds a descriptor each, indefinitely.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an HTTP/1 client has to send a request's headers.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an `/auth/*` body may take to arrive. It is at most 16 KiB, and
/// these routes are open to anyone: a client that trickles one is holding a
/// connection, not signing in.
const AUTH_BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// The pause after a failed `accept`. The listener is still good (the usual
/// cause is running out of descriptors), so serving goes on after it.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long an interaction may run once it has produced a head.
///
/// Minutes rather than seconds, because a signing session legitimately takes
/// them and a stream doing its job must not be cut off for being slow. What
/// this bounds is the other case: a peer that opened an interaction and then
/// went quiet still holds its tenant's only slot, and without a ceiling it
/// holds it until the process ends.
const DEFAULT_MAX_INTERACTION: Duration = Duration::from_secs(300);

/// The store one call runs in.
struct GuestInstance {
    store: Store<State>,
    /// Shared with this store's epoch callback.
    progress: Arc<StreamProgress>,
}

/// What the guest is, by what it exports.
enum GuestShape {
    /// `wasi:http/incoming-handler`: the guest serves HTTP itself.
    Http(ProxyPre<State>),
    /// `enclave:rpc/service`: the runtime ends gRPC, and the guest sees messages.
    Rpc(grpc::ServerPre<State>),
}

/// Where a guest's response head arrives.
type Head = std::result::Result<
    hyper::Response<HyperOutgoingBody>,
    wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
>;

/// One call, ready to run in the store it was prepared in.
///
/// An HTTP guest's instance and request already live in that store, as guest resources: an
/// instance binds to one store, and separating them would produce a handle that looks usable and
/// resolves against the wrong memory. An rpc guest is instantiated inside the call, where its
/// streams can run.
// One per request, made and moved once: boxing either variant would buy nothing.
#[allow(clippy::large_enum_variant)]
enum Call<B> {
    Http {
        proxy: wasmtime_wasi_http::p2::bindings::Proxy,
        req: Resource<HostIncomingRequest>,
        out: Resource<HostResponseOutparam>,
    },
    Rpc {
        pre: grpc::ServerPre<State>,
        req: hyper::Request<Counting<B>>,
        head: tokio::sync::oneshot::Sender<Head>,
    },
}

impl<B> Call<B>
where
    B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
{
    async fn run(self, store: &mut Store<State>) -> wasmtime::Result<()> {
        match self {
            Call::Http { proxy, req, out } => {
                proxy
                    .wasi_http_incoming_handler()
                    .call_handle(store, req, out)
                    .await
            }
            Call::Rpc { pre, req, head } => grpc::serve(store, &pre, req, head).await,
        }
    }
}

/// A compiled guest plus the environment its instances are built from.
///
/// Compilation and `instantiate_pre` happen once, at startup: per-request
/// instantiation is then cheap, and — more usefully inside an enclave — a
/// component that will not compile fails at boot rather than on the first
/// request to arrive.
pub struct ServeHandle {
    shape: GuestShape,
    background_pre: InstancePre<State>,
    tasks: Option<Arc<crate::tasks::TaskQueue>>,
    notify: Option<Arc<crate::notify::Notifier>>,
    /// What each wallet's dealt share is recomputed from, for `enclave:signer`.
    signer_keys: Option<Arc<crate::signer::Keys>>,
    /// Where each invocation's trace and metrics go. Every invocation gets a context, so a guest's
    /// telemetry calls always resolve.
    telemetry: crate::telemetry::Telemetry,
    guest: Arc<GuestEnvironment>,
    /// One request at a time for callers with no resolved tenant.
    ///
    /// There is no identity to separate them by, so they are treated as one:
    /// anonymous requests serialise against each other and against nothing
    /// else. Unbounded would let anyone with a socket multiply wasm linear
    /// memories, which is the same exhaustion a per-tenant lock prevents for
    /// everybody who *is* identified.
    anonymous: Arc<tokio::sync::Mutex<()>>,
    /// Ceiling on producing a response head. See [`ServeHandle::watchdog`].
    timeout: Duration,
    /// How long a call may run after its head is out. See `supervise`.
    max_interaction: Duration,
    /// Per-client filesystems, when the deployment asked for them.
    ///
    /// `None` is the original model and stays the default: one filesystem, a
    /// fresh instance per request, every request serialised against every
    /// other. Turning this on changes what two clients can do at the same time,
    /// which is a property a guest may have been relying on — so it is opted
    /// into, and PCR0 records the choice.
    tenancy: Option<Arc<Tenancy>>,
}

/// Everything needed to give a client their own corner of the filesystem.
///
/// No backends and no mounting: there is one filesystem, and a client costs a
/// directory in it. What is per-client is the *view* — which directory the
/// guest calls `/` — and a lock.
pub struct Tenancy {
    pool: TenantPool,
}

impl std::fmt::Debug for Tenancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tenancy")
            .field("tenants", &self.pool.len())
            .finish_non_exhaustive()
    }
}

impl Tenancy {
    pub fn new(limits: PoolLimits) -> Self {
        Tenancy {
            pool: TenantPool::new(limits),
        }
    }

    pub fn pool(&self) -> &TenantPool {
        &self.pool
    }
}

impl ServeHandle {
    /// The storage the guest's tenants live on.
    pub fn zfs(&self) -> &Arc<crate::store::zfs::Zfs> {
        self.guest.zfs()
    }

    /// An `Engine` configured for the watchdog, plus the ticker that drives it.
    ///
    /// Epoch interruption is what makes a spinning guest interruptible at all:
    /// without it, wasm that never yields cannot be stopped, and
    /// `tokio::task::abort` has no await point to act on. A dedicated thread
    /// advances the epoch independently of Tokio workers and exits when the
    /// last engine handle is dropped.
    pub fn engine_with_watchdog() -> Result<Engine> {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        // Async exports, streams and futures: what an `enclave:rpc/service` guest is made of.
        // A `wasi:http` guest uses none of it and is served as before.
        config.wasm_component_model_async(true);
        let engine = Engine::new(&config)?;

        let ticker = engine.weak();
        // The ticker must run even when guest CPU loops occupy every Tokio
        // worker. An async ticker on that same executor cannot guarantee it.
        std::thread::Builder::new()
            .name("guest-epoch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(EPOCH_TICK);
                    // A weak handle, so this thread cannot keep a dropped engine
                    // alive — it simply stops when the engine goes.
                    match ticker.upgrade() {
                        Some(engine) => engine.increment_epoch(),
                        None => break,
                    }
                }
            })?;
        Ok(engine)
    }

    pub fn new(engine: &Engine, component_bytes: &[u8], guest: GuestEnvironment) -> Result<Self> {
        let component = Component::new(engine, component_bytes)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("compiling guest component")?;

        let mut linker = build_linker(engine).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("adding wasi:http to the linker")?;

        let instance_pre: InstancePre<State> = linker
            .instantiate_pre(&component)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("pre-instantiating guest component")?;
        let shape = match grpc::ServerPre::new(instance_pre.clone()) {
            Ok(pre) => GuestShape::Rpc(pre),
            Err(rpc) => GuestShape::Http(ProxyPre::new(instance_pre.clone()).map_err(|http| {
                anyhow::anyhow!(
                    "the guest exports neither enclave:rpc/service ({rpc}) nor \
                     wasi:http/incoming-handler ({http})"
                )
            })?),
        };

        Ok(ServeHandle {
            background_pre: instance_pre,
            tasks: None,
            notify: None,
            signer_keys: None,
            telemetry: Default::default(),
            shape,
            guest: Arc::new(guest),
            anonymous: Arc::new(tokio::sync::Mutex::new(())),
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_interaction: DEFAULT_MAX_INTERACTION,
            tenancy: None,
        })
    }

    /// The environment instances are built from — the runtime's own
    /// filesystem, the clock, and the entropy source.
    pub fn environment(&self) -> &Arc<GuestEnvironment> {
        &self.guest
    }

    /// Give each authenticated client their own filesystem and lock.
    pub fn with_tenancy(mut self, tenancy: Arc<Tenancy>) -> Self {
        self.tenancy = Some(tenancy);
        self
    }

    pub fn with_tasks(mut self, queue: Arc<crate::tasks::TaskQueue>) -> Result<Self> {
        anyhow::ensure!(
            self.tenancy.is_some(),
            "background tasks require tenant isolation"
        );
        self.tasks = Some(queue);
        Ok(self)
    }

    /// Let the guest wake its tenant's devices.
    ///
    /// Tenant isolation is required for the same reason tasks require it: a
    /// device belongs to a tenant, and without tenancy there is no tenant to
    /// bind an enrolment to.
    pub fn with_notify(mut self, notifier: Arc<crate::notify::Notifier>) -> Result<Self> {
        anyhow::ensure!(
            self.tenancy.is_some(),
            "notifications require tenant isolation"
        );
        self.notify = Some(notifier);
        Ok(self)
    }

    /// Where `enclave:signer` reads each tenant's wallet key: the auth
    /// endpoints' keys, since registration made them and sign-in opened them.
    pub fn with_signer_keys(mut self, keys: Arc<crate::signer::Keys>) -> Self {
        self.signer_keys = Some(keys);
        self
    }

    /// Ship guest spans and metrics. No tenancy requirement: an anonymous request is attributed
    /// to the anonymous tenant, as its filesystem is.
    pub fn with_telemetry(mut self, telemetry: crate::telemetry::Telemetry) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// One task attempt: a fresh instance, its `run-task`, and then whatever it wrote anchored.
    async fn run_task(
        &self,
        queue: &Arc<crate::tasks::TaskQueue>,
        job: &crate::tasks::Job,
    ) -> Result<Vec<u8>> {
        let work = async {
            let state = self.tenant_state(job.tenant).await?;
            let mut store = Store::new(self.background_pre.engine(), state);
            // Yield every tick, even in CPU-only loops, so the wall deadline
            // can cancel both guest code and async host calls.
            store.set_epoch_deadline(1);
            store.epoch_deadline_async_yield_and_update(1);
            let instance = self.background_pre.instantiate_async(&mut store).await?;
            store.data_mut().tasks = Some(crate::tasks::TaskContext {
                queue: queue.clone(),
                tenant: job.tenant,
                interactive: false,
            });
            store.data_mut().notify =
                self.notify
                    .as_ref()
                    .map(|notifier| crate::notify::NotifyContext {
                        notifier: notifier.clone(),
                        tenant: job.tenant,
                        interactive: false,
                    });
            store.data_mut().telemetry = Some(
                self.telemetry
                    .context(job.tenant, crate::telemetry::Invocation::Task),
            );
            let run = instance
                .get_typed_func::<(String, Vec<u8>), (std::result::Result<Vec<u8>, String>,)>(
                    &mut store, "run-task",
                )?;
            let (result,) = run
                .call_async(&mut store, (job.run_id(), job.payload.clone()))
                .await?;
            let bytes = result.map_err(anyhow::Error::msg)?;
            anyhow::ensure!(bytes.len() <= 64 * 1024, "task result exceeds 64 KiB");
            Ok(bytes)
        };
        let outcome = tokio::time::timeout(queue.limits.timeout, work)
            .await
            .context("background task deadline exceeded")
            .and_then(|outcome| outcome);
        // Whatever the guest wrote reaches the anchor before its outcome is recorded or anyone
        // is woken, failed attempts included: they may have written too.
        self.guest
            .zfs()
            .anchor_tenant(job.tenant)
            .await
            .context("anchoring a task's writes")?;
        outcome
    }

    /// Deliver a tenant's staged wakes — for the task worker, once the outcome the
    /// wake announces is recorded.
    fn deliver_wakes(&self, tenant: [u8; 16]) {
        if let Some(notify) = &self.notify {
            notify.deliver_staged(tenant);
        }
    }

    /// Drop a tenant's staged wakes unsent — if the outcome could not be
    /// recorded.
    fn drop_wakes(&self, tenant: [u8; 16]) {
        if let Some(notify) = &self.notify {
            notify.drop_staged(tenant);
        }
    }

    /// Override the response-head deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override how long an interaction may run once it has answered.
    ///
    /// Distinct from [`ServeHandle::with_timeout`], and the distinction is the
    /// point: one bounds how long a guest may take to *start* answering, the
    /// other how long it may go on. A stream that is healthy for minutes is
    /// normal; a tenant's slot held for hours is not.
    pub fn with_max_interaction(mut self, max_interaction: Duration) -> Self {
        self.max_interaction = max_interaction;
        self
    }

    /// Ticks of [`EPOCH_TICK`] a guest gets before the epoch traps it.
    ///
    /// Deliberately **shorter** than the timeout, and that ordering is the
    /// whole mechanism. The epoch is the only thing that can stop wasm which
    /// never yields; `tokio::task::abort` needs an await point and a spinning
    /// guest never reaches one. Give the deadline slack *past* the timeout —
    /// as a first attempt here did, to get a tidier error message — and the
    /// abort fires first against a guest nothing can interrupt, which leaves
    /// the task spinning for the life of the process and hangs runtime
    /// shutdown. The nicer message cost the entire guarantee.
    ///
    /// So the epoch fires first and the guest traps with a real reason. The
    /// timeout stays as the backstop for what the epoch cannot see: a guest
    /// parked in a *host* call, where there is no wasm executing to interrupt
    /// but there is an await point for `abort` to land on.
    fn watchdog(&self) -> u64 {
        let ticks = self.timeout.as_millis() / EPOCH_TICK.as_millis();
        (ticks.saturating_sub(2)).max(1) as u64
    }

    /// Run one request, in an instance built for it and discarded after it.
    ///
    /// `scheme` is what the *client* used, which is not what this function was
    /// reached over: with TLS terminated upstream of here the connection is
    /// plaintext, but the guest must be told `https` or it will build wrong
    /// absolute URLs and set wrong cookie flags.
    ///
    /// Generic over the request body rather than taking
    /// `hyper::body::Incoming`, which cannot be constructed outside a real
    /// connection — the whole dispatch path would be untestable without a
    /// listening socket.
    ///
    /// `tenant` is required rather than defaulted, so every caller has to
    /// answer the question. It is **not** a way around the gate: with one
    /// configured, [`serve_connection`] spends a token before it gets here and
    /// there is no path that reaches a guest without one.
    pub async fn handle<B>(
        &self,
        scheme: Scheme,
        mut req: hyper::Request<B>,
        tenant: Option<&[u8; 16]>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Before anything else touches the request, and before it is handed to
        // `new_incoming_request`, which copies the header map into the guest
        // verbatim. This is the only ingress, so this is the only place the
        // header can be made trustworthy.
        apply_tenant(tenant, &mut req);

        // Concurrency is per tenant, and the lock that enforces it is taken
        // inside each arm — the per-tenant mutex for an identified caller, one
        // shared lock for the rest. There is no global ceiling: two tenants
        // have nothing to queue on, which is the whole point of giving them
        // separate directories and separate instances.
        //
        // Either lock is held until the guest task finishes, body included, so
        // a tenant's second request waits for its first to be genuinely done
        // rather than merely to have produced headers.
        match (&self.tenancy, tenant) {
            (Some(tenancy), Some(tenant)) => {
                self.in_tenant(tenancy.clone(), *tenant, scheme, req).await
            }
            // No tenant resolved. Either the deployment configured no gate, or
            // the caller reached a path that does not identify itself — and
            // with no identity there is nothing to separate them by, so they
            // share one lock and one filesystem: the runtime's own.
            _ => self.in_fresh_instance(scheme, req).await,
        }
    }

    /// One request, in this client's own filesystem and a fresh instance.
    ///
    /// The lock is held for the whole call — including the body, because
    /// `call_handle` does not return until the guest has finished writing it —
    /// and it is what serialises this client against **itself and nothing
    /// else**. Two clients holding two different locks over two different
    /// filesystems is the entire point: their commits do not queue, because
    /// there is nothing for them to queue on.
    async fn in_tenant<B>(
        &self,
        tenancy: Arc<Tenancy>,
        tenant_id: [u8; 16],
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        let head = req.method() == hyper::Method::HEAD;
        // Checked out before the lock is taken, so the eviction sweep can see
        // this tenant is busy and leave it alone. The guard releases that mark
        // however the request ends.
        let checkout = tenancy.pool.checkout(&tenant_id);
        // Owned, so it can move into the task below and outlive this function.
        let guard = checkout.slot().lock().clone().lock_owned().await;

        // Attached when the token was granted, with the key its owner sent:
        // a release reaches no tenant's data any other way.
        let dir = self.guest.zfs().attached_dir(tenant_id)?;

        let mut instance = self.store_for(&dir)?;
        instance.store.data_mut().tasks =
            self.tasks.as_ref().map(|queue| crate::tasks::TaskContext {
                queue: queue.clone(),
                tenant: tenant_id,
                interactive: true,
            });
        instance.store.data_mut().notify =
            self.notify
                .as_ref()
                .map(|notifier| crate::notify::NotifyContext {
                    notifier: notifier.clone(),
                    tenant: tenant_id,
                    interactive: true,
                });
        instance.store.data_mut().telemetry = Some(
            self.telemetry
                .context(tenant_id, crate::telemetry::Invocation::Request),
        );
        // Here and nowhere else: signing needs the wallet's half of each round,
        // so its owner connected.
        instance.store.data_mut().signer =
            self.signer_keys
                .as_ref()
                .map(|keys| crate::signer::SignerContext {
                    keys: keys.clone(),
                    tenant: tenant_id,
                });
        let progress = instance.progress.clone();
        // Wrapped before it becomes the guest's, which is the last point the
        // runtime holds it.
        let req = req.map(|body| Counting::new(body, progress.clone()));
        let (call, receiver) = self.prepare(&mut instance.store, scheme, req).await?;

        let zfs = self.guest.zfs().clone();
        let notify = self.notify.clone();
        let (anchored_tx, anchored_rx) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn(async move {
            // Moved in so the lock outlives the response head: this tenant's
            // next request waits until the call has finished writing its body,
            // which is what makes "one active request per tenant" true rather
            // than "one set of headers at a time". The instance is moved in
            // too, so it dies with the call however the call ends — finished,
            // trapped or aborted.
            let _guard = guard;
            let _checkout = checkout;
            let mut instance = instance;
            let result = call.run(&mut instance.store).await;
            if result.is_err() {
                tracing::warn!("guest trapped; its instance dies with the call");
            }
            // Still under the tenant's lock, so its next request cannot write
            // before this one's writes are anchored.
            let anchored = zfs.anchor_tenant(tenant_id).await;
            // Any wake the guest raised rides on that anchor: delivered once the
            // writes it announces are durable, dropped if they are not.
            if let Some(notify) = &notify {
                match anchored {
                    Ok(()) => notify.deliver_staged(tenant_id),
                    Err(_) => notify.drop_staged(tenant_id),
                }
            }
            let _ = anchored_tx.send(body_outcome(&result, anchored));
            result
        });

        let response =
            await_head(self.timeout, self.max_interaction, task, receiver, progress).await?;
        after_anchor(response, anchored_rx, head).await
    }

    /// A background or message run's state: the tenant's dataset as `/`. One
    /// that has gone is not brought back by work running in its name.
    async fn tenant_state(&self, tenant: [u8; 16]) -> Result<State> {
        let dir = self.guest.zfs().attached_dir(tenant)?;
        self.guest.new_state(Some(&dir))
    }

    /// A store whose guest sees `dir` as `/`, watched by the epoch.
    ///
    /// Every tenant request gets one, used for that call and dropped with it.
    fn store_for(&self, dir: &std::path::Path) -> Result<GuestInstance> {
        let mut store = Store::new(
            self.background_pre.engine(),
            self.guest.new_state(Some(dir))?,
        );
        let progress = Arc::new(StreamProgress::new());
        store.set_epoch_deadline(self.watchdog());
        self.arm_watchdog(&mut store, progress.clone());
        Ok(GuestInstance { store, progress })
    }

    /// Ready one call in `store`, and where its response head will arrive.
    ///
    /// An HTTP guest is instantiated here, so one that will not start fails
    /// before anything is spawned; an rpc guest is instantiated inside the call.
    async fn prepare<B>(
        &self,
        store: &mut Store<State>,
        scheme: Scheme,
        req: hyper::Request<Counting<B>>,
    ) -> Result<(Call<B>, tokio::sync::oneshot::Receiver<Head>)>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let call = match &self.shape {
            GuestShape::Http(pre) => {
                let proxy = pre
                    .instantiate_async(&mut *store)
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
                    .context("instantiating the guest")?;
                let req = store.data_mut().http().new_incoming_request(scheme, req)?;
                let out = store.data_mut().http().new_response_outparam(sender)?;
                Call::Http { proxy, req, out }
            }
            GuestShape::Rpc(pre) => Call::Rpc {
                pre: pre.clone(),
                req,
                head: sender,
            },
        };
        Ok((call, receiver))
    }

    /// Let a call that is moving bytes outlive the budget; keep one that is not
    /// on exactly the schedule it had before.
    ///
    /// The deadline set beside this is what a request/response call gets, and
    /// for anything that finishes inside the timeout nothing here ever runs.
    /// When it does expire, the question stops being "how long has this taken"
    /// and becomes "is this still a conversation" — because a signing session
    /// legitimately open for minutes and a guest spinning in a loop are
    /// indistinguishable by elapsed time and obvious by traffic.
    ///
    /// `Yield` rather than `Continue`: extending alone leaves a guest that
    /// makes progress *and* spins between frames with no await point for
    /// `await_head`'s abort to land on. Yielding creates one every tick, which
    /// costs a reschedule per [`EPOCH_TICK`] and keeps the abort path real.
    ///
    /// Note what this deliberately cannot see: a guest parked in a *host* call
    /// executes no wasm, so no epoch check is reached and nothing here fires.
    /// That gap is the idle supervisor's, not this one's.
    fn arm_watchdog(&self, store: &mut Store<State>, progress: Arc<StreamProgress>) {
        let silent = EPOCH_TICK * SILENT_TICKS_BEFORE_TRAP;
        store.epoch_deadline_callback(move |_| {
            // A single tick at a time once the budget is spent, so the
            // question gets asked again promptly rather than handing out
            // another full budget on one frame of evidence.
            if progress.still_working(SILENT_TICKS_BEFORE_TRAP) {
                Ok(UpdateDeadline::Yield(1))
            } else {
                Err(wasmtime::Error::msg(format!(
                    "the guest ran {silent:?} past its budget without moving a byte \
                     in either direction"
                )))
            }
        });
    }

    /// The only dispatch path without a gate. A fresh store, a fresh instance,
    /// both dropped when the request ends — so nothing survives but what was
    /// written to the anonymous directory, and anchored.
    async fn in_fresh_instance<B>(
        &self,
        scheme: Scheme,
        req: hyper::Request<B>,
    ) -> Result<hyper::Response<HyperOutgoingBody>>
    where
        B: hyper::body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
        B::Error: Into<wasmtime_wasi_http::p2::bindings::http::types::ErrorCode>,
    {
        // Anonymous callers are one identity, so they queue behind each other.
        // Taken before the store is built: an instance is a wasm linear memory,
        // and building one per waiting request is the exhaustion this prevents.
        let head = req.method() == hyper::Method::HEAD;
        let anonymous = self.anonymous.clone().lock_owned().await;

        // One shared pool, keyed by this release, and only its `data`
        // dataset: never anything that would hand an unauthenticated guest a
        // tenant's records.
        let dir = self.guest.zfs().anonymous_dir().await?;
        let GuestInstance {
            mut store,
            progress,
        } = self.store_for(&dir)?;
        store.data_mut().telemetry = Some(
            self.telemetry
                .context(ANONYMOUS, crate::telemetry::Invocation::Request),
        );
        let req = req.map(|body| Counting::new(body, progress.clone()));
        let (call, receiver) = self.prepare(&mut store, scheme, req).await?;
        let zfs = self.guest.zfs().clone();
        let (anchored_tx, anchored_rx) = tokio::sync::oneshot::channel();

        // The guest runs in its own task so it can keep streaming a body after
        // the status line and headers have gone out. The lock goes with it, so
        // it is held for the whole call rather than released at the head.
        let task = tokio::task::spawn(async move {
            let _anonymous = anonymous;
            let mut store = store;
            let result = call.run(&mut store).await;
            let anchored = zfs.anchor_tenant(ANONYMOUS).await;
            let _ = anchored_tx.send(body_outcome(&result, anchored));
            result
        });

        let response =
            await_head(self.timeout, self.max_interaction, task, receiver, progress).await?;
        after_anchor(response, anchored_rx, head).await
    }

    /// Prove the guest instantiates, before a single request depends on it.
    ///
    /// Builds one instance and drops it. Narrower than it looks, and worth
    /// saying so: `Component::new` and `instantiate_pre` already fail at
    /// startup for a guest that will not compile or whose imports do not
    /// resolve. What this adds is the *initialiser* — a guest that traps or
    /// hangs in `start` would otherwise answer 500 to every request while the
    /// enclave looked perfectly healthy from the outside.
    ///
    /// The cost is running that initialiser once more than strictly necessary,
    /// which is nothing new: [`ServeHandle::in_fresh_instance`] runs it on
    /// every request already.
    pub async fn verify_instantiates(&self) -> Result<()> {
        let mut store = Store::new(self.background_pre.engine(), self.guest.new_state(None)?);
        // A deadline of its own, or a guest that hangs in `start` would hang
        // the boot rather than failing it.
        store.set_epoch_deadline(self.watchdog());
        let started = match &self.shape {
            GuestShape::Http(pre) => pre.instantiate_async(&mut store).await.map(drop),
            GuestShape::Rpc(pre) => pre.instantiate_async(&mut store).await.map(drop),
        };
        started
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .context("instantiating the guest")?;
        if self.tasks.is_some() {
            let instance = self.background_pre.instantiate_async(&mut store).await?;
            instance
                .get_typed_func::<(String, Vec<u8>), (std::result::Result<Vec<u8>, String>,)>(
                    &mut store, "run-task",
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))
                .context("background tasks require the run-task export")?;
        }
        Ok(())
        // The store and the instance drop here. Nothing is kept: an instance
        // that outlived this call would be an instance two requests could
        // share, which is the whole thing this design refuses.
    }
}

/// A tenant's turn: its lock, and the checkout that keeps its slot from being reused while the
/// lock is held. Dropped in that order.
struct TenantTurn {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _checkout: crate::serve::pool::Checkout,
}

#[async_trait::async_trait]
impl crate::tasks::Runner for ServeHandle {
    fn turn(&self, tenant: [u8; 16]) -> Option<Box<dyn Send>> {
        let checkout = self.tenancy.as_ref()?.pool.checkout(&tenant);
        let guard = checkout.slot().lock().clone().try_lock_owned().ok()?;
        Some(Box::new(TenantTurn {
            _guard: guard,
            _checkout: checkout,
        }))
    }

    async fn run(
        &self,
        queue: &Arc<crate::tasks::TaskQueue>,
        job: &crate::tasks::Job,
    ) -> Result<Vec<u8>> {
        self.run_task(queue, job).await
    }

    fn wakes(&self, tenant: [u8; 16], deliver: bool) {
        if deliver {
            self.deliver_wakes(tenant);
        } else {
            self.drop_wakes(tenant);
        }
    }
}

/// Wait for the response head, and leave the guest task to finish the body.
///
/// Returns as soon as the guest has set a response. Deliberately: the body may
/// still be streaming out of the task, and hyper cannot read it until this
/// returns — waiting for the task here would deadlock body delivery.
///
/// **The permit is not here.** It lives in the spawned task, so a slot is freed
/// when the guest is genuinely finished — or when its task fails or is aborted
/// — rather than when its headers happened to appear. A free function rather
/// than a method because that lifetime is worth testing on its own, without an
/// engine and a compiled component to build a `ServeHandle` around.
/// Bound how long an interaction may run, once its head is out.
///
/// Until this existed nothing watched the call after `await_head` returned: the
/// `JoinHandle` was dropped, which detaches, and the only remaining limits were
/// the epoch — which a guest parked in a host call never reaches, because it
/// executes no wasm — and `wasi:http`'s hardcoded ten-minute between-bytes
/// ceiling. A client that opened a stream and then said nothing held its
/// tenant's single slot for as long as it liked.
///
/// A wall clock is the right instrument here precisely where the epoch is the
/// wrong one. A guest blocked in a host call *is* at an await point inside
/// `call_handle`, so `abort` reaches it — and dropping the task drops the
/// tenant's guard, the pool checkout, and the instance, none of which it can
/// hand back.
///
/// Detached deliberately: the caller is returning a response body that hyper is
/// about to stream, so it cannot hold this. The handle races the deadline and
/// goes away when either finishes.
fn supervise(max_interaction: Duration, task: tokio::task::JoinHandle<wasmtime::Result<()>>) {
    tokio::task::spawn(async move {
        let mut task = task;
        if tokio::time::timeout(max_interaction, &mut task)
            .await
            .is_err()
        {
            tracing::info!(
                limit = ?max_interaction,
                "an interaction reached its deadline; abandoning it and freeing its tenant"
            );
            task.abort();
        }
    });
}

async fn await_head(
    timeout: Duration,
    max_interaction: Duration,
    task: tokio::task::JoinHandle<wasmtime::Result<()>>,
    receiver: tokio::sync::oneshot::Receiver<
        std::result::Result<
            hyper::Response<HyperOutgoingBody>,
            wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
        >,
    >,
    progress: Arc<StreamProgress>,
) -> Result<hyper::Response<HyperOutgoingBody>> {
    let waited = match tokio::time::timeout(timeout, receiver).await {
        Ok(waited) => waited,
        Err(_) => {
            // Nothing arrived in time. The epoch should already have
            // trapped a spinning guest — see `watchdog` — so reaching here
            // means the guest is parked somewhere the epoch cannot see,
            // which is exactly where `abort` does work.
            // Aborting drops the task's locals, and the permit is one of
            // them — so an abandoned guest frees its slot rather than
            // holding it for the life of the process.
            task.abort();
            anyhow::bail!("guest did not produce a response within {timeout:?}; abandoned");
        }
    };

    match waited {
        // Wrapped on the way out, which is the first point the runtime holds
        // it again: from here the count follows what hyper actually drains,
        // so a guest writing into a buffer nobody reads earns no extension.
        Ok(Ok(resp)) => {
            // From here `await_head` is out of the picture, so the watchdog may
            // stop racing it and start judging silence on its merits.
            progress.head_sent();
            supervise(max_interaction, task);
            Ok(resp.map(|body| {
                use http_body_util::BodyExt;
                Counting::new(body, progress).boxed_unsync()
            }))
        }
        Ok(Err(e)) => Err(e.into()),
        // The sender dropped with the `Store`, so the guest returned or
        // trapped without setting a response. Whatever the task says is
        // the real error; "never set a response" alone would send someone
        // looking in the wrong place.
        Err(_) => {
            match task.await {
                Ok(Ok(())) => {
                    anyhow::bail!("guest returned without calling response-outparam::set")
                }
                Ok(Err(e)) => Err(anyhow::anyhow!(e.to_string())
                    .context("guest failed before setting a response")),
                Err(e) => Err(anyhow::Error::from(e).context("guest task panicked")),
            }
        }
    }
}

/// Refuse a resumed session, and say so.
///
/// Serving configs disable resumption (see `serve::tls`), so this should be
/// unreachable — it is here because the alternative to being unreachable is
/// attesting a certificate the connection was never authenticated under, and
/// that failure would be silent. A loud refusal is the cheaper mistake.
fn resumed<S>(stream: &tokio_rustls::server::TlsStream<S>, peer: SocketAddr) -> bool {
    let (_, connection) = stream.get_ref();
    if connection.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
        tracing::error!(
            %peer,
            "refusing a resumed TLS session: the certificate it was authenticated \
             under cannot be established, so nothing about it can be attested"
        );
        return true;
    }
    false
}

/// The tenant callers without a gate share. A tenant id is a hash of a group
/// key, so none is ever all zeroes.
use crate::tenant::ANONYMOUS;

/// Hold a response's end until what produced it is anchored, so no client can
/// see it finish before the writes it may describe would survive the host.
///
/// A streamed body (no `Content-Length`) streams as the guest writes it — an
/// event stream or a gRPC call stays one — and only its end, trailers
/// included, waits. A sized body is held whole: a client counting
/// `Content-Length` would otherwise have all of it, and act on it, first.
///
/// A response that may not have a body — to a HEAD, or a 1xx, 204 or 304 —
/// is held whole too. hyper never polls a body it may not send, so streamed
/// it would be complete the moment its head went out.
// ponytail: a sized body is buffered in memory; hold back just its last frame
// if a guest ever serves large sized downloads.
async fn after_anchor(
    response: hyper::Response<HyperOutgoingBody>,
    anchored: tokio::sync::oneshot::Receiver<Result<()>>,
    head: bool,
) -> Result<hyper::Response<HyperOutgoingBody>> {
    let status = response.status();
    let bodiless = head
        || status.is_informational()
        || status == hyper::StatusCode::NO_CONTENT
        || status == hyper::StatusCode::NOT_MODIFIED;
    if !bodiless
        && !response
            .headers()
            .contains_key(hyper::header::CONTENT_LENGTH)
    {
        use http_body_util::BodyExt;
        return Ok(response.map(|inner| {
            AnchoredBody {
                inner,
                anchored,
                phase: Phase::Streaming,
            }
            .boxed_unsync()
        }));
    }
    let (parts, body) = response.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .to_bytes();
    anchored
        .await
        .context("the guest's call ended before its writes were anchored")??;
    Ok(hyper::Response::from_parts(parts, full(body)))
}

/// How a response body may end, once the call is over and its writes are anchored.
///
/// A guest that traps mid-body leaves a body that ends exactly like a finished one
/// (`wasmtime-wasi-http` reads a dropped `outgoing-body` as its end), so the call's
/// own result is the only thing that tells a truncated body from a complete one.
/// The writes are anchored either way; only the response is refused.
fn body_outcome<T, E>(call: &std::result::Result<T, E>, anchored: Result<()>) -> Result<()> {
    match call {
        Ok(_) => anchored,
        Err(_) => Err(anyhow::anyhow!(
            "the guest stopped before its response was complete"
        )),
    }
}

/// A streamed body whose end waits for the call's outcome ([`body_outcome`]).
/// A call that failed, or writes that were not anchored, abort the stream
/// rather than end it, so no client sees a clean finish.
struct AnchoredBody {
    inner: HyperOutgoingBody,
    anchored: tokio::sync::oneshot::Receiver<Result<()>>,
    phase: Phase,
}

enum Phase {
    Streaming,
    /// The guest's body is done; its trailers, if any, wait with its end.
    Holding(Option<hyper::body::Frame<bytes::Bytes>>),
    Finished,
}

impl hyper::body::Body for AnchoredBody {
    type Data = bytes::Bytes;
    type Error = wasmtime_wasi_http::p2::bindings::http::types::ErrorCode;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::future::Future;
        use std::task::Poll;
        let this = self.get_mut();
        loop {
            match &mut this.phase {
                Phase::Streaming => match std::pin::Pin::new(&mut this.inner).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) if frame.is_data() => {
                        return Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Ready(Some(Ok(trailers))) => this.phase = Phase::Holding(Some(trailers)),
                    Poll::Ready(None) => this.phase = Phase::Holding(None),
                    other => return other,
                },
                Phase::Holding(trailers) => {
                    let outcome = match std::pin::Pin::new(&mut this.anchored).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(Ok(()))) => Ok(trailers.take()),
                        Poll::Ready(Ok(Err(e))) => Err(format!("{e:#}")),
                        Poll::Ready(Err(_)) => Err("the call ended before it was anchored".into()),
                    };
                    this.phase = Phase::Finished;
                    return Poll::Ready(match outcome {
                        Ok(trailers) => trailers.map(Ok),
                        Err(why) => {
                            tracing::error!(error = %why, "aborting a response that did not end cleanly");
                            Some(Err(Self::Error::InternalError(Some(why))))
                        }
                    });
                }
                Phase::Finished => return Poll::Ready(None),
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.phase, Phase::Finished)
    }
}

/// A fixed body, in the shape the guest dispatch wants.
fn full(bytes: bytes::Bytes) -> HyperOutgoingBody {
    use http_body_util::BodyExt;
    http_body_util::Full::new(bytes)
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed_unsync()
}

/// A refusal, in one sentence and no detail.
fn refused(status: hyper::StatusCode, detail: &str) -> hyper::Response<HyperOutgoingBody> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full(bytes::Bytes::from(
            serde_json::json!({ "error": detail }).to_string(),
        )))
        .expect("response is well formed")
}

/// Serve one connection, whatever it is wrapped in.
///
/// Generic over the stream so the two arms above — TLS and plaintext — share one
/// body instead of two copies of it. Both satisfy the bound, so this
/// monomorphises and costs nothing at runtime.
///
/// The service closure is built here rather than by the caller because it must
/// capture `client`, and `client` does not exist until the handshake has
/// completed.
/// Everything a connection needs that is the same for every connection.
///
/// Grouped because the per-connection values — the certificate this handshake
/// presented — are the interesting ones, and a signature where they are lost
/// among six process-wide `Arc`s hides that.
#[derive(Clone)]
pub struct Routes {
    guest: Arc<ServeHandle>,
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    attestor: Option<Arc<ResponseAttestor>>,
    scheme: Scheme,
}

async fn serve_connection<S>(
    io: S,
    routes: Routes,
    // The leaf this connection's handshake actually presented, loaded once at
    // accept time. `None` for plaintext.
    certificate: Option<Vec<u8>>,
    // Boxed rather than `hyper::Error`: the protocol is chosen per connection
    // now, and `auto::Builder` reports failures from whichever of the two it
    // ended up speaking.
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Routes {
        guest,
        auth,
        gate,
        attestor,
        scheme,
    } = routes;
    let certificate = certificate.map(Arc::new);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let guest = guest.clone();
        let auth = auth.clone();
        let gate = gate.clone();
        let attestor = attestor.clone();
        let certificate = certificate.clone();
        // Cloned per request because the closure is `Fn` — it runs again for
        // every request on a kept-alive connection.
        let scheme = scheme.clone();
        async move {
            // A nonce on the options calls, the only ones whose answers carry
            // a document (`ATTESTED_CALLS`); no other call takes one. Checked
            // before the route runs, so a call refused for it leaves no
            // challenge or half-finished registration behind. Without sign-in
            // there are no `/auth` routes, and those paths are the guest's like
            // any other.
            let attested_call =
                auth.is_some() && crate::auth::ATTESTED_CALLS.contains(&req.uri().path());
            let nonce = if attested_call {
                match nonce_from_headers(req.headers()) {
                    Ok(nonce) => Some(nonce),
                    Err(e) => {
                        // No document on this one: there is no nonce to bind, and
                        // one the runtime chose would prove nothing.
                        tracing::debug!(reason = %e, "refused an options call with no usable nonce");
                        return Ok::<_, anyhow::Error>(refused(
                            hyper::StatusCode::BAD_REQUEST,
                            &e.to_string(),
                        ));
                    }
                }
            } else {
                None
            };

            // Only where a client still has to work out who it is talking to:
            // the options calls, each the first of its operation. The auth
            // route decides, and no refusal is attested.
            //
            // A client identifies the enclave on that answer — its document
            // binds the certificate it was served — and then pins that
            // certificate for the rest of the operation. TLS proves the peer
            // holds its private key, which the certificate itself, being
            // public, does not; so "the same certificate" and "the same
            // enclave" are one statement, and the verify call and the
            // interaction need no document of their own. Each would cost an
            // NSM signature, and the device is the throughput ceiling —
            // `CONCURRENT_DOCUMENTS` is 4.
            //
            // The SHA-256 of the certificate this connection was served: what a
            // client's signature binds, so one made for anyone else's is refused.
            let served = certificate
                .as_ref()
                .map(|c| nitro_attestation::sha256(c))
                .unwrap_or(crate::auth::approval::NO_CERTIFICATE);

            // Made once the auth route has answered, never for a guest response:
            // an `/auth` answer is small and whole, so nothing is stranded if
            // attesting it fails.
            let (mut response, attest) = route(req, guest, auth, gate, scheme, &served).await?;
            let document = match (&attestor, &nonce) {
                (Some(attestor), Some(nonce)) if attest => {
                    match attestor
                        .document(certificate.as_ref().map(|c| c.as_slice()), nonce)
                        .await
                    {
                        Ok(document) => Some(document),
                        Err(e) => {
                            // 503, not a dropped connection. A bare reset
                            // is indistinguishable to a client from a
                            // network fault or an interceptor, and this is
                            // the one signal that says "this enclave will
                            // not vouch for itself".
                            tracing::error!(error = %e, "could not attest a response");
                            let mut response = refused(
                                hyper::StatusCode::SERVICE_UNAVAILABLE,
                                "this response could not be attested",
                            );
                            response.headers_mut().insert(
                                hyper::header::CONNECTION,
                                hyper::header::HeaderValue::from_static("close"),
                            );
                            return Ok(response);
                        }
                    }
                }
                // Either the deployment does not attest, or this is not one of
                // the two answers that carry a document.
                _ => None,
            };
            match document {
                Some(document) => crate::serve::attest::attach(&mut response, document),
                // Not "leave it as it is": a response the runtime did not
                // attest must not carry the header at all, or a guest could
                // put one there itself.
                None => crate::serve::attest::strip(&mut response),
            }
            Ok(response)
        }
    });

    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    // hyper only enforces its header-read timeout once it has a timer: without
    // one, a peer could hold a connection open by never finishing its headers.
    builder
        .http1()
        .keep_alive(true)
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    // A stream carrying nothing is indistinguishable from a peer that has gone
    // away, and a peer that has gone away is still holding its tenant's slot.
    // PING is the only thing at this layer that can tell them apart.
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(20));
    builder.serve_connection(TokioIo::new(io), service).await
}

/// Everything that decides what a response *is*, with attestation stripped out.
///
/// A separate function so the closure above has exactly one exit: that is what
/// makes "no response leaves unattested" and "a guest cannot own the header"
/// single facts rather than five places to audit.
async fn route(
    req: hyper::Request<hyper::body::Incoming>,
    guest: Arc<ServeHandle>,
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    scheme: Scheme,
    served: &[u8; 32],
) -> Result<(hyper::Response<HyperOutgoingBody>, bool)> {
    {
        {
            let method = req.method().clone();
            let path = req.uri().path().to_string();

            // `/auth/` is checked first and is not forwardable: a guest able
            // to answer there could hand out its own tokens, which is the same
            // as having none.
            if let Some(auth) = &auth {
                if path.starts_with(crate::auth::AUTH_PREFIX) {
                    // The routes take bytes rather than a stream, so the body is
                    // read here, bounded in size while it is read and in time
                    // overall: these routes are open to anyone who can connect.
                    // A body that says up front it is too large is refused
                    // before any of it is read.
                    let too_large = || {
                        Ok((
                            refused(
                                hyper::StatusCode::PAYLOAD_TOO_LARGE,
                                "request body too large",
                            ),
                            false,
                        ))
                    };
                    if hyper::body::Body::size_hint(req.body()).lower()
                        > crate::auth::routes::MAX_BODY as u64
                    {
                        return too_large();
                    }
                    let limited = http_body_util::Limited::new(
                        req.into_body(),
                        crate::auth::routes::MAX_BODY,
                    );
                    let read = tokio::time::timeout(
                        AUTH_BODY_TIMEOUT,
                        http_body_util::BodyExt::collect(limited),
                    )
                    .await;
                    let Ok(read) = read else {
                        return Ok((
                            refused(hyper::StatusCode::REQUEST_TIMEOUT, "request body too slow"),
                            false,
                        ));
                    };
                    let body = match read {
                        Ok(collected) => collected.to_bytes(),
                        Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                            return too_large();
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "reading an auth request body");
                            return Ok((
                                refused(hyper::StatusCode::BAD_REQUEST, "malformed request"),
                                false,
                            ));
                        }
                    };
                    if let Some(answer) = auth.handle(&method, &path, &body, served).await {
                        return Ok((answer.response, answer.attest));
                    }
                    return Ok((
                        refused(hyper::StatusCode::NOT_FOUND, "no such endpoint"),
                        false,
                    ));
                }
            }

            // Everything else is the guest, and **nothing reaches the guest
            // without an unspent interaction token.** With no gate configured
            // the runtime is unauthenticated by deliberate choice —
            // development, and the QEMU harness.
            let tenant = match &gate {
                Some(gate) => match gate.redeem(&req) {
                    Ok(verified) => {
                        // Rebuilt so the token cannot reach the guest. The body
                        // is forwarded as it arrives, never buffered: an
                        // interaction may be a stream, and there is no hash to
                        // hold it still for any more.
                        let mut rebuilt = hyper::Request::builder()
                            .method(req.method().clone())
                            .uri(req.uri().clone());
                        for (name, value) in req.headers() {
                            if !crate::auth::AUTH_HEADERS
                                .iter()
                                .any(|h| name.as_str() == *h)
                            {
                                rebuilt = rebuilt.header(name, value);
                            }
                        }
                        use http_body_util::BodyExt;
                        let body = req
                            .into_body()
                            .map_err(wasmtime_wasi_http::p2::bindings::http::types::ErrorCode::from)
                            .boxed_unsync();
                        let rebuilt = rebuilt.body(body).expect("request is well formed");
                        return Ok((
                            guest
                                .handle(scheme, rebuilt, Some(&verified.tenant_id))
                                .await?,
                            false,
                        ));
                    }
                    Err(denied) => {
                        // Logged in full, answered in one sentence: which check
                        // failed is the runtime's business, and telling a
                        // caller would tell them which guess to refine.
                        tracing::info!(%path, reason = %denied, "refused an unauthorized interaction");
                        return Ok((refused(denied.status(), denied.public_message()), false));
                    }
                },
                None => None,
            };
            Ok((guest.handle(scheme, req, tenant.as_ref()).await?, false))
        }
    }
}

/// The accept loop: TLS if configured, `/enclave/*` to the runtime, the rest
/// to the guest.
///
/// Nothing about the guest changes between the plaintext and TLS paths, which
/// is why dispatch lives in [`ServeHandle`] and this only decides what wraps
/// it.
pub struct Server {
    guest: Arc<ServeHandle>,
    /// Produces the per-response proof. `None` leaves the runtime behaving
    /// exactly as it did before attestation existed, nonce included.
    attestor: Option<Arc<ResponseAttestor>>,
    /// `/auth/*`, and the gate every other request must pass.
    ///
    /// Both or neither: routes that issue challenges nobody checks would be
    /// worse than no routes at all, and a gate with no way to get a challenge
    /// would refuse everything forever.
    auth: Option<Arc<AuthEndpoints>>,
    gate: Option<Arc<Gate>>,
    /// The one certificate every connection is served, and told about.
    tls: Option<Arc<TlsIdentity>>,
    addr: SocketAddr,
}

impl Server {
    pub fn new(guest: ServeHandle, addr: SocketAddr) -> Self {
        Server {
            guest: Arc::new(guest),
            attestor: None,
            auth: None,
            gate: None,
            tls: None,
            addr,
        }
    }

    /// Require a token, bought with a signed approval, for everything the guest
    /// could see.
    pub fn with_authentication(mut self, auth: Arc<AuthEndpoints>, gate: Arc<Gate>) -> Self {
        self.auth = Some(auth);
        self.gate = Some(gate);
        self
    }

    pub fn with_attestor(mut self, attestor: Arc<ResponseAttestor>) -> Self {
        self.attestor = Some(attestor);
        self
    }

    pub fn with_tls(mut self, certificate: Arc<TlsIdentity>) -> Self {
        self.tls = Some(certificate);
        self
    }

    /// Accept connections until the process is stopped.
    pub async fn run(self) -> Result<()> {
        // Dropping the server cancels the task consumer and its owned worker set. The
        // consumer only ends if it cannot go on, and then serving stops with it.
        let mut scheduler = tokio::task::JoinSet::new();
        if let Some(queue) = &self.guest.tasks {
            anyhow::ensure!(
                self.gate.is_some(),
                "background tasks require authentication"
            );
            let runner: Arc<dyn crate::tasks::Runner> = self.guest.clone();
            scheduler.spawn(queue.clone().run(runner));
        }
        let listener = TcpListener::bind(self.addr)
            .await
            .with_context(|| format!("binding {}", self.addr))?;
        tracing::info!(
            addr = %listener.local_addr()?,
            tls = self.tls.is_some(),
            attestation = self.attestor.is_some(),
            "serving"
        );

        // What the *client* used. With TLS terminated here the guest is still
        // told `https`, or it would build wrong absolute URLs and set wrong
        // cookie flags.
        let scheme = if self.tls.is_some() {
            Scheme::Https
        } else {
            Scheme::Http
        };
        let tls = self.tls;

        loop {
            let (client, peer) = tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok(connection) => connection,
                    // One failed accept is one connection lost, not the listener:
                    // stopping here would take every tenant down with it.
                    Err(e) => {
                        tracing::warn!(error = %e, "accepting a connection failed");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                },
                ended = scheduler.join_next(), if !scheduler.is_empty() => {
                    ended.context("scheduler disappeared")???;
                    anyhow::bail!("scheduler unexpectedly stopped");
                }
            };
            let routes = Routes {
                guest: self.guest.clone(),
                auth: self.auth.clone(),
                gate: self.gate.clone(),
                attestor: self.attestor.clone(),
                // `Scheme` is not `Copy`, and the service closure is `Fn` — it
                // may run per request on a kept-alive connection.
                scheme: scheme.clone(),
            };
            let tls = tls.clone();

            tokio::task::spawn(async move {
                // The service closure is built *inside* each arm below, after
                // the handshake, because that is the only point at which the
                // peer's certificate exists. Built out here — as it was — the
                // connection's identity could never reach a request.
                let result = match tls {
                    Some(identity) => {
                        // Every connection is served the one certificate this
                        // boot made, and is told about exactly that one.
                        let acceptor = tokio_rustls::TlsAcceptor::from(identity.config.clone());
                        let handshake =
                            tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(client));
                        let Ok(handshake) = handshake.await else {
                            tracing::debug!(%peer, "TLS handshake timed out");
                            return;
                        };
                        match handshake {
                            Ok(stream) => {
                                if resumed(&stream, peer) {
                                    return;
                                }
                                serve_connection(
                                    stream,
                                    routes,
                                    Some(identity.certificate_der.clone()),
                                )
                                .await
                            }
                            Err(e) => {
                                // Routine: scanners, health checks, and clients
                                // that reject the certificate.
                                tracing::debug!(%peer, error = %e, "TLS handshake failed");
                                return;
                            }
                        }
                    }
                    // No TLS, so no certificate and no identity. Whatever the
                    // client says about itself is discarded, same as any other
                    // unauthenticated connection.
                    None => serve_connection(client, routes, None).await,
                };
                if let Err(e) = result {
                    tracing::debug!(%peer, error = %e, "connection ended");
                }
            });
        }
    }
}

/// Compile the guest, build the server described by `config`, and serve until
/// the process is stopped.
pub async fn serve_component(
    component_bytes: &[u8],
    guest: GuestEnvironment,
    mut config: ServeConfig,
) -> Result<()> {
    // wasmtime 44 enables async at the engine level when the `async` feature
    // is on; `Config::async_support` is a no-op. Same as `run_component`.
    let engine = ServeHandle::engine_with_watchdog()?;
    let telemetry = std::mem::take(&mut config.telemetry);
    let mut handle = ServeHandle::new(&engine, component_bytes, guest)?
        .with_timeout(config.request_timeout)
        .with_max_interaction(config.max_interaction)
        .with_telemetry(telemetry.clone());
    if let Some(tenancy) = &config.tenancy {
        handle = handle.with_tenancy(tenancy.clone());
    }
    // Whether there are tasks is the guest's to say, by exporting `run-task`: the guest is
    // measured into PCR16, so its exports already are the decision, and a setting beside them
    // could only disagree.
    let runs_tasks = handle
        .background_pre
        .component()
        .get_export_index(None, "run-task")
        .is_some();
    if let Some(tasks) = config.background_tasks.take().filter(|_| runs_tasks) {
        anyhow::ensure!(
            config.authentication.is_some(),
            "the guest exports run-task, and background tasks require authentication"
        );
        let queue = tasks
            .open(
                handle.environment().zfs().clone(),
                handle.environment().clock().clone(),
            )
            .await?;
        handle = handle.with_tasks(queue)?;
    }
    let mut notify_forwarder = None;
    if let Some(notify) = config.notify.take() {
        anyhow::ensure!(
            config.authentication.is_some(),
            "notifications require authentication: the tenant a wake belongs to comes \
             from a verified sign-in, and without a gate there is none"
        );
        let registry =
            crate::notify::DeviceRegistry::open(handle.environment().zfs().clone()).await?;
        // Plaintext only where an endpoint override asked for it, which is the
        // emulator harness pointing at a local stub.
        let plaintext = notify
            .endpoint
            .as_deref()
            .is_some_and(|e| e.starts_with("http://"));
        let transport = Arc::new(crate::notify::HttpsTransport::new(plaintext)?);
        let mut client = crate::notify::pinpoint::client(notify, transport)?;

        let clock = handle.environment().clock().clone();
        let now = {
            use wasmtime_wasi::HostWallClock;
            clock.now().as_millis().min(u64::MAX as u128) as u64
        };
        // Bounded, and never fatal for a transient failure. A push service
        // must not be what decides whether the enclave binds its listener —
        // but an application that can never deliver, or a role that may not
        // send, is a deployment mistake, and finding it now beats finding it
        // the first time somebody needed a wake signal.
        match tokio::time::timeout(
            crate::notify::NOTIFY_STARTUP_PROBE_TIMEOUT,
            client.probe(now),
        )
        .await
        {
            Ok(Ok(())) => {
                tracing::info!("notifications are configured and the application can deliver")
            }
            Ok(Err(crate::notify::SendError::Refused(detail))) => {
                anyhow::bail!("the push application cannot deliver: {detail}")
            }
            Ok(Err(e)) => tracing::warn!(
                error = %e,
                "could not reach the push service at startup; wake signals will retry"
            ),
            Err(_) => tracing::warn!(
                "the push service did not answer at startup; wake signals will retry"
            ),
        }

        let (notifier, forwarder) = crate::notify::start(registry, clock, client);
        notify_forwarder = Some(forwarder);
        handle = handle.with_notify(notifier)?;
    }

    // Before the listener binds. A guest that will not instantiate should stop
    // the enclave, not the first client unlucky enough to arrive.
    handle.verify_instantiates().await?;

    if let Some((auth, _)) = &config.authentication {
        handle = handle.with_signer_keys(auth.keys().clone());
    }

    let mut server = Server::new(handle, config.addr);
    match config.authentication {
        Some((auth, gate)) => server = server.with_authentication(auth, gate),
        None => tracing::warn!(
            "serving with NO authentication: every request reaches the guest without a \
             signed approval. Only a testing build without ENCLAVE_OPERATOR_MASTER serves like \
             this: a production build always signs in through its operator master."
        ),
    }

    match (config.certificate.take(), &config.attestation) {
        (Some(identity), attestation) => {
            if let Some(nsm) = attestation {
                // Both options calls carry a proof, so the device is on the
                // path of every registration and sign-in.
                let attestor = Arc::new(ResponseAttestor::new(nsm.clone(), component_bytes));

                // Checked once, here, with the largest nonce a client may send.
                // A document too large for a header is a property of this
                // deployment's certificate chain, and a runtime that cannot
                // attest its responses should refuse to start rather than
                // refuse every request. This is also the first call to the
                // device, so an NSM that will not answer is found now.
                match attestor.verify_fits().await {
                    Ok(bytes) => {
                        tracing::info!(
                            document_header_bytes = bytes,
                            "attesting registration and sign-in answers"
                        )
                    }
                    Err(e) => anyhow::bail!(
                        "this runtime cannot attest its responses: {e}. Every request would \
                         be refused, so it will not start."
                    ),
                }
                server = server.with_attestor(attestor);
            }

            server = server.with_tls(identity);
        }
        (None, Some(_)) => {
            anyhow::bail!(
                "attestation was requested without TLS. A document binds the serving \
                 certificate, so without one it would promise a binding it does not have."
            );
        }
        (None, None) => {
            tracing::warn!(
                "serving plaintext HTTP with no attestation; \
                 inside an enclave this exposes every request to the parent instance"
            );
        }
    }

    let served = server.run().await;
    // Drained after serving, so a wake raised by the last request still has its
    // chance to land. Bounded by the forwarder's own flush deadline.
    if let Some(forwarder) = notify_forwarder {
        forwarder.shutdown().await;
    }
    // The same for the last invocations' traces and the metrics still aggregating.
    telemetry.shutdown().await;
    served
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use tokio::sync::oneshot;

    type HeadResult = std::result::Result<
        hyper::Response<HyperOutgoingBody>,
        wasmtime_wasi_http::p2::bindings::http::types::ErrorCode,
    >;

    fn head() -> HeadResult {
        Ok(hyper::Response::new(full(bytes::Bytes::from_static(
            b"body",
        ))))
    }

    /// A guest task, as the dispatch paths build one: it holds `lock` for the
    /// whole call, sets a response head part way through, and finishes only
    /// when told to.
    fn guest_task<L: Send + 'static>(
        lock: L,
        set_head: oneshot::Sender<HeadResult>,
        finish: oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<wasmtime::Result<()>> {
        tokio::task::spawn(async move {
            let _lock = lock;
            let _ = set_head.send(head());
            let _ = finish.await;
            Ok(())
        })
    }

    /// The property the whole design rests on: a tenant's second request waits
    /// for its first to be *finished*, not merely to have produced headers.
    #[tokio::test(flavor = "multi_thread")]
    async fn one_tenant_serialises_against_itself() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let task = guest_task(held, set_head, finished);

        // The head is out, and the guest is still writing its body.
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
        .await
        .expect("head");

        let second = tenant.clone().lock_owned();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second)
                .await
                .is_err(),
            "a second request for this tenant started while the first was still running"
        );

        let _ = finish.send(());
        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "the tenant's lock was not released when its guest finished"
        );
    }

    /// And the other half: two tenants have nothing to queue on. This is what
    /// the removed global semaphore used to prevent.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_tenants_run_at_the_same_time() {
        let alice = Arc::new(tokio::sync::Mutex::new(()));
        let bob = Arc::new(tokio::sync::Mutex::new(()));

        let (alice_head, alice_receiver) = oneshot::channel();
        let (alice_finish, alice_finished) = oneshot::channel();
        let alice_task = guest_task(alice.clone().lock_owned().await, alice_head, alice_finished);
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            alice_task,
            alice_receiver,
            Arc::new(StreamProgress::new()),
        )
        .await
        .expect("alice's head");

        // Alice is mid-body. Bob must not be waiting on her.
        let (bob_head, bob_receiver) = oneshot::channel();
        let (bob_finish, bob_finished) = oneshot::channel();
        let bob_lock = tokio::time::timeout(Duration::from_millis(100), bob.clone().lock_owned())
            .await
            .expect("bob queued behind alice");
        let bob_task = guest_task(bob_lock, bob_head, bob_finished);
        let bob_response = tokio::time::timeout(
            Duration::from_secs(5),
            await_head(
                Duration::from_secs(5),
                Duration::from_secs(300),
                bob_task,
                bob_receiver,
                Arc::new(StreamProgress::new()),
            ),
        )
        .await
        .expect("bob's head did not arrive while alice was running")
        .expect("bob's head");
        assert_eq!(bob_response.status(), 200);

        let _ = alice_finish.send(());
        let _ = bob_finish.send(());
    }

    /// Callers with no resolved tenant are one identity, so they queue behind
    /// each other rather than multiplying wasm instances.
    #[tokio::test(flavor = "multi_thread")]
    async fn anonymous_callers_share_one_slot() {
        let anonymous = Arc::new(tokio::sync::Mutex::new(()));
        let held = anonymous.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let task = guest_task(held, set_head, finished);
        await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
        .await
        .expect("head");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), anonymous.clone().lock_owned())
                .await
                .is_err(),
            "a second anonymous request ran alongside the first"
        );
        let _ = finish.send(());
    }

    /// A guest that never answers is aborted, and abort drops the task's
    /// locals — so an abandoned request must not hold its tenant's lock
    /// forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_abandoned_guest_releases_its_tenant() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (_set_head, receiver) = oneshot::channel::<HeadResult>();

        let task = tokio::task::spawn(async move {
            let _lock = held;
            std::future::pending::<()>().await;
            Ok(())
        });

        let error = await_head(
            Duration::from_millis(50),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
        .await
        .expect_err("a guest that never answers should be abandoned");
        assert!(format!("{error:#}").contains("abandoned"), "{error:#}");

        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "an abandoned guest kept its tenant's lock"
        );
    }

    /// A guest that fails without setting a response still releases its lock.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_guest_releases_its_tenant() {
        let tenant = Arc::new(tokio::sync::Mutex::new(()));
        let held = tenant.clone().lock_owned().await;
        let (set_head, receiver) = oneshot::channel::<HeadResult>();

        let task = tokio::task::spawn(async move {
            let _lock = held;
            drop(set_head);
            Err(wasmtime::Error::msg("guest trapped"))
        });

        let error = await_head(
            Duration::from_secs(5),
            Duration::from_secs(300),
            task,
            receiver,
            Arc::new(StreamProgress::new()),
        )
        .await
        .expect_err("a trap without a response is an error");
        assert!(format!("{error:#}").contains("guest trapped"), "{error:#}");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), tenant.clone().lock_owned())
                .await
                .is_ok(),
            "a failed guest kept its tenant's lock"
        );
    }

    /// A response with no body to stream — to a HEAD, or a 204 or 304 — goes
    /// out only once its writes are anchored, and not at all if they are not.
    /// hyper never polls such a body, so a streamed one would end at its head.
    #[tokio::test]
    async fn a_bodiless_response_waits_for_its_anchor() {
        let cases = [
            (hyper::StatusCode::NO_CONTENT, false),
            (hyper::StatusCode::NOT_MODIFIED, false),
            (hyper::StatusCode::OK, true),
        ];
        for (status, head) in cases {
            let response = || {
                hyper::Response::builder()
                    .status(status)
                    .body(full(bytes::Bytes::new()))
                    .unwrap()
            };
            let (anchored, anchoring) = oneshot::channel();
            let mut waiting = Box::pin(after_anchor(response(), anchoring, head));
            assert!(
                tokio::time::timeout(Duration::from_millis(50), &mut waiting)
                    .await
                    .is_err(),
                "{status} (head: {head}) went out before its anchor"
            );
            anchored.send(Ok(())).unwrap();
            assert_eq!(waiting.await.unwrap().status(), status);

            let (anchored, anchoring) = oneshot::channel();
            anchored
                .send(Err(anyhow::anyhow!("anchor failed")))
                .unwrap();
            assert!(
                after_anchor(response(), anchoring, head).await.is_err(),
                "{status} (head: {head}) went out though its anchor failed"
            );
        }
    }
}
