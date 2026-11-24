//! The exported library, driven over stdin and stdout: for an app's own tests.
//!
//! An app that runs a policy's conversations itself is written in TypeScript against `Session`,
//! `Stream` and `signRound`. Those live in a native module, which Node cannot load. This is the
//! same exported API with one JSON object per line in and out, over the runtime in process and
//! the real policy guest, so the app's code is tested against what it will meet on a phone.
//!
//! ```console
//! $ POLICY_WASM=<path to policy.wasm> cargo run -p vtxos-uniffi --example bridge
//! {"ready":true,"record":{…}}
//! {"id":1,"op":"call","method":"/cosigner.v1.Cosigner/DeviceCount","request":""}
//! {"id":1,"ok":"…"}
//! ```
//!
//! Or over an enclave that is already up, by its address and pins: a dev enclave in QEMU
//! (`tests/qemu/dev-enclave.sh`), which prints all four.
//!
//! ```console
//! $ ENCLAVE_URL=https://127.0.0.1:8443 ENCLAVE_TRUST_ROOT=<trust-root.der> \
//!     ENCLAVE_PCR0=<hex> ENCLAVE_PCR16=<hex> cargo run -p vtxos-uniffi --example bridge
//! ```
//!
//! Bytes are hex. A wallet is registered at start, and one session is open on it throughout.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use enclave_runtime::testing::Enclave as Harness;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;
use vtxos_uniffi::{Commitment, Enclave, Pins, Session, Stream, VtxosError};

struct Bridge {
    session: Arc<Session>,
    streams: Mutex<HashMap<u64, Arc<Stream>>>,
    opened: std::sync::atomic::AtomicU64,
}

fn bytes(v: &Value, field: &str) -> Result<Vec<u8>, String> {
    let text = v
        .get(field)
        .and_then(Value::as_str)
        .ok_or(format!("`{field}` is missing"))?;
    hex::decode(text).map_err(|e| format!("`{field}` is not hex: {e}"))
}

fn failure(e: VtxosError) -> Value {
    let message = e.to_string();
    match e {
        VtxosError::Status { code, message } => {
            json!({ "kind": "Status", "code": code, "message": message })
        }
        VtxosError::Auth { status, message } => {
            json!({ "kind": "Auth", "status": status, "message": message })
        }
        VtxosError::Attestation { .. } => json!({ "kind": "Attestation", "message": message }),
        VtxosError::Pinning { .. } => json!({ "kind": "Pinning", "message": message }),
        VtxosError::WrongPasskey => json!({ "kind": "WrongPasskey", "message": message }),
        VtxosError::Protocol { .. } => json!({ "kind": "Protocol", "message": message }),
        VtxosError::Transport { .. } => json!({ "kind": "Transport", "message": message }),
    }
}

impl Bridge {
    async fn stream(&self, request: &Value) -> Result<Arc<Stream>, Value> {
        let id = request.get("stream").and_then(Value::as_u64).unwrap_or(0);
        self.streams
            .lock()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| json!({ "kind": "Bridge", "message": format!("no stream {id}") }))
    }

    async fn answer(&self, request: &Value) -> Result<Value, Value> {
        let bad = |message: String| json!({ "kind": "Bridge", "message": message });
        let text = |field: &str| {
            request
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| bad(format!("`{field}` is missing")))
        };
        match request.get("op").and_then(Value::as_str).unwrap_or("") {
            "call" => {
                let body = bytes(request, "request").map_err(bad)?;
                let reply = self.session.call(text("method")?, body).await;
                reply.map(|r| json!(hex::encode(r))).map_err(failure)
            }
            "stream" => {
                let stream = self
                    .session
                    .stream(text("method")?)
                    .await
                    .map_err(failure)?;
                let id = self
                    .opened
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                self.streams.lock().await.insert(id, stream);
                Ok(json!(id))
            }
            "send" => {
                let message = bytes(request, "message").map_err(bad)?;
                let stream = self.stream(request).await?;
                stream
                    .send(message)
                    .await
                    .map(|()| Value::Null)
                    .map_err(failure)
            }
            "next" => {
                let stream = self.stream(request).await?;
                let next = stream.next().await.map_err(failure)?;
                Ok(next.map(|m| json!(hex::encode(m))).unwrap_or(Value::Null))
            }
            "finish" => {
                self.stream(request).await?.finish();
                Ok(Value::Null)
            }
            "cancel" => {
                self.stream(request).await?.cancel();
                Ok(Value::Null)
            }
            "signRound" => {
                let list = |field: &str| {
                    request
                        .get(field)
                        .and_then(Value::as_array)
                        .cloned()
                        .ok_or_else(|| bad(format!("`{field}` is missing")))
                };
                let messages = list("messages")?
                    .iter()
                    .map(|m| hex::decode(m.as_str().unwrap_or("")).map_err(|e| bad(e.to_string())))
                    .collect::<Result<Vec<_>, _>>()?;
                let commitments = list("commitments")?
                    .iter()
                    .map(|c| {
                        Ok(Commitment {
                            hiding: bytes(c, "hiding").map_err(bad)?,
                            binding: bytes(c, "binding").map_err(bad)?,
                        })
                    })
                    .collect::<Result<Vec<_>, Value>>()?;
                let rounds = self
                    .session
                    .sign_round(messages, commitments)
                    .map_err(failure)?;
                Ok(Value::Array(
                    rounds
                        .into_iter()
                        .map(|r| {
                            json!({
                                "hiding": hex::encode(r.hiding),
                                "binding": hex::encode(r.binding),
                                "share": hex::encode(r.share),
                            })
                        })
                        .collect(),
                ))
            }
            other => Err(bad(format!("no such op: {other:?}"))),
        }
    }
}

#[tokio::main]
async fn main() {
    // The enclave: one that is already up, or the runtime in process serving `POLICY_WASM`. The
    // harness is kept until the end, because dropping it stops the runtime.
    let (url, trust_root, pcr0, pcr16, _harness) = match std::env::var("ENCLAVE_URL") {
        Ok(url) => {
            let pin = |name: &str| {
                std::env::var(name)
                    .unwrap_or_else(|_| panic!("{name}: with ENCLAVE_URL, that enclave's pin"))
            };
            let root = std::fs::read(pin("ENCLAVE_TRUST_ROOT"))
                .expect("read ENCLAVE_TRUST_ROOT, a DER certificate");
            (url, root, pin("ENCLAVE_PCR0"), pin("ENCLAVE_PCR16"), None)
        }
        Err(_) => {
            let path =
                std::env::var_os("POLICY_WASM").expect("POLICY_WASM: the policy guest to serve");
            let harness = Harness::builder(std::fs::read(path).expect("read POLICY_WASM"))
                .notify()
                .background_tasks()
                .start()
                .await
                .expect("the runtime starts");
            (
                harness.url(),
                harness.trust_root(),
                hex::encode(harness.pcr0()),
                hex::encode(harness.pcr16()),
                Some(harness),
            )
        }
    };

    let root = base64::engine::general_purpose::STANDARD.encode(trust_root);
    let lines: Vec<&str> = root
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    let enclave = Enclave::new(
        url,
        Pins {
            trust_root_pem: Some(format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )),
            pcr0,
            pcr16,
            max_age_secs: 300,
        },
    )
    .expect("the enclave's address and pins");
    let prf = vec![0x42; 32];
    let record = enclave.register(prf.clone()).await.expect("registered");
    let ready = json!({
        "ready": true,
        "record": serde_json::from_str::<Value>(&vtxos_uniffi::encode_record(record.clone()))
            .expect("a record is JSON"),
    });
    let bridge = Arc::new(Bridge {
        session: enclave.open(record, prf).expect("the passkey opens it"),
        streams: Mutex::new(HashMap::new()),
        opened: std::sync::atomic::AtomicU64::new(0),
    });
    println!("{ready}");

    // Each request answers in its own task: a read that is waiting must not hold up a send.
    let mut requests = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = requests.next_line().await {
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            println!(
                "{}",
                json!({ "error": { "kind": "Bridge", "message": "not JSON" } })
            );
            continue;
        };
        let bridge = bridge.clone();
        tokio::spawn(async move {
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            match bridge.answer(&request).await {
                Ok(ok) => println!("{}", json!({ "id": id, "ok": ok })),
                Err(error) => println!("{}", json!({ "id": id, "error": error })),
            }
        });
    }
}
