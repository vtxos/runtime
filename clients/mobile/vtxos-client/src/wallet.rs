//! A wallet, opened: the phone's share in memory, and the ceremonies that use it.
//!
//! Each ceremony is one stream to the policy guest, signed in for that stream alone. The guest
//! builds every transaction and asks for the phone's half of each signature; the phone talks to
//! the ASP and relays what it says, because the guest has no socket of its own.

use std::sync::Arc;
use std::time::Duration;

use ark::client::{exit_delay_value, server_info, Info};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, ScriptBuf, XOnlyPublicKey};
use enclave_auth::client::Client;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::asp::Asp;
use crate::enclave::Enclave;
use crate::error::{Error, Result};
use crate::exits::{Exit, Plan};
use crate::frost;
use crate::guest::{guest, status};
use crate::proto::guest::{
    renew_client_msg, renew_server_msg, send_client_msg, send_server_msg, AspEvent, BoardOpen,
    BoardingUtxo, DelegateRenewed, IntentRegistered, RenewClientMsg, RenewDelegate, RenewOpen,
    RenewServerMsg, RenewSigned, SendClientMsg, SendFinalized, SendOpen, SendServerMsg, SendSigned,
    SendSubmitted, VtxoInput, WalletRound,
};
use crate::proto::wallet::ArkInfo as WireInfo;

/// A VTXO this wallet holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vtxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// The exit delay it was made under: the unilateral one, or the boarding one for a VTXO that
    /// came in by boarding.
    pub exit_delay: u32,
    /// When its batch expires, Unix seconds, as the indexer reports it.
    pub expires_at: i64,
}

/// What a renewal of the delegate should arrange alongside it.
#[derive(Debug, Clone, Default)]
pub struct Renewal {
    /// An on-chain address the user controls: each VTXO gets a signed exit paying it.
    pub exit_address: Option<String>,
    /// A push token, so the guest can wake this phone when it renews in the background.
    pub device_token: Option<String>,
}

/// A renewed delegate: the guest may now refresh these VTXOs on its own, from `valid_at_secs`.
#[derive(Debug, Clone)]
pub struct Renewed {
    pub valid_at_secs: u64,
    pub margin_secs: u64,
    /// The outpoints it covers.
    pub covered: Vec<String>,
    pub device_enrolled: bool,
    /// One signed exit per covered VTXO that has one, each checked.
    pub exits: Vec<Exit>,
}

/// A send, accepted by the ASP.
#[derive(Debug, Clone)]
pub struct Sent {
    pub ark_txid: String,
    pub renewed: Option<Renewed>,
}

/// A round settled: boarding, or a refresh.
#[derive(Debug, Clone)]
pub struct Settled {
    pub commitment_txid: String,
    pub vtxo_txid: String,
    pub vtxo_vout: u32,
    pub amount_sats: u64,
    pub exit_delay: u32,
    pub renewed: Option<Renewed>,
}

/// A wallet with its share rebuilt.
pub struct Wallet {
    enclave: Arc<Enclave>,
    asp: Arc<Asp>,
    client: Client,
}

impl Wallet {
    pub fn new(enclave: Arc<Enclave>, asp: Arc<Asp>, client: Client) -> Self {
        Wallet {
            enclave,
            asp,
            client,
        }
    }

    /// The group key, x-only: whose VTXOs these are.
    fn owner(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&self.client.group_key()[1..]).expect("a group key is a point")
    }

    fn identifier(&self) -> Vec<u8> {
        self.client.key_package().identifier.serialize().to_vec()
    }

    /// The ASP's parameters, as ark-core takes them and as the guest's wire carries them.
    async fn info(&self) -> Result<(Info, WireInfo)> {
        let answer = self.asp.info().await?;
        let wire = WireInfo {
            signer_pubkey: answer.signer_pubkey.clone(),
            forfeit_pubkey: answer.forfeit_pubkey.clone(),
            forfeit_address: answer.forfeit_address.clone(),
            checkpoint_tapscript: answer.checkpoint_tapscript.clone(),
            network: answer.network.clone(),
            session_duration: answer.session_duration,
            unilateral_exit_delay: answer.unilateral_exit_delay,
            boarding_exit_delay: answer.boarding_exit_delay,
            vtxo_min_amount: answer.vtxo_min_amount,
            dust: answer.dust,
        };
        let info = server_info(answer).map_err(Error::Asp)?;
        Ok((info, wire))
    }

    fn address(&self, info: &Info, delay: u32, boarding: bool) -> Result<String> {
        let (owner, asp) = (self.owner().to_string(), info.signer_pk.to_string());
        let derived = if boarding {
            ark::client::boarding_address(&owner, &asp, delay, info.network)
        } else {
            ark::client::ark_address(&owner, &asp, delay, info.network)
        };
        derived.map_err(Error::Protocol)
    }

    /// Where to receive off-chain.
    pub async fn ark_address(&self) -> Result<String> {
        let (info, _) = self.info().await?;
        self.address(
            &info,
            exit_delay_value(info.unilateral_exit_delay).map_err(Error::Asp)?,
            false,
        )
    }

    /// Where to send on-chain funds to bring them in with [`Self::board`].
    pub async fn boarding_address(&self) -> Result<String> {
        let (info, _) = self.info().await?;
        self.address(
            &info,
            exit_delay_value(info.boarding_exit_delay).map_err(Error::Asp)?,
            true,
        )
    }

    /// The VTXOs this wallet holds, from the ASP's indexer: those under its unilateral delay and
    /// those it boarded.
    pub async fn vtxos(&self) -> Result<Vec<Vtxo>> {
        let (info, _) = self.info().await?;
        self.held(&info).await
    }

    pub async fn balance(&self) -> Result<u64> {
        Ok(self.vtxos().await?.iter().map(|v| v.amount_sats).sum())
    }

    async fn held(&self, info: &Info) -> Result<Vec<Vtxo>> {
        let mut delays = vec![
            exit_delay_value(info.unilateral_exit_delay).map_err(Error::Asp)?,
            exit_delay_value(info.boarding_exit_delay).map_err(Error::Asp)?,
        ];
        delays.dedup();
        let mut held = Vec::new();
        for delay in delays {
            let script = ark::client::vtxo_script_pubkey_hex(
                &self.owner().to_string(),
                &info.signer_pk.to_string(),
                delay,
                info.network,
            )
            .map_err(Error::Protocol)?;
            for v in self.asp.vtxos(&script).await? {
                let outpoint = v.outpoint.unwrap_or_default();
                held.push(Vtxo {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    amount_sats: v.amount,
                    exit_delay: delay,
                    expires_at: v.expires_at,
                });
            }
        }
        Ok(held)
    }

    /// The held set once the indexer shows `settled` holds: what a delegate renewed after a
    /// ceremony must cover. The ASP indexes a new VTXO a moment after it exists.
    async fn held_once(&self, info: &Info, settled: impl Fn(&[Vtxo]) -> bool) -> Result<Vec<Vtxo>> {
        for _ in 0..30 {
            let held = self.held(info).await?;
            if settled(&held) {
                return Ok(held);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(Error::Asp("the indexer never showed the new VTXOs".into()))
    }

    fn exit_script(&self, info: &Info, renewal: &Renewal) -> Result<ScriptBuf> {
        match &renewal.exit_address {
            None => Ok(ScriptBuf::new()),
            Some(address) => Ok(address
                .parse::<Address<NetworkUnchecked>>()
                .map_err(|e| Error::Protocol(format!("exit address {address:?}: {e}")))?
                .require_network(info.network)
                .map_err(|e| Error::Protocol(format!("exit address {address:?}: {e}")))?
                .script_pubkey()),
        }
    }

    fn sign(
        &self,
        cosigner: &str,
        messages: &[Vec<u8>],
        commitments: &[crate::proto::guest::Commitment],
    ) -> Result<Vec<WalletRound>> {
        frost::answer(
            self.client.key_package(),
            self.client.runtime(),
            cosigner,
            messages,
            commitments,
        )
    }

    /// Enrol a push token, so the guest's background work can wake this phone.
    pub async fn register_device(&self, token: &str) -> Result<()> {
        crate::guest::register_device(&self.enclave, &self.client, token).await
    }

    /// Stop waking the phone that holds `token`.
    pub async fn forget_device(&self, token: &str) -> Result<()> {
        crate::guest::forget_device(&self.enclave, &self.client, token).await
    }

    /// How many devices this wallet wakes.
    pub async fn device_count(&self) -> Result<u32> {
        crate::guest::device_count(&self.enclave, &self.client).await
    }

    /// Send `amount_sats` off-chain to the Ark address `address`. With `renewal`, the delegate is
    /// renewed over what is held afterwards, on the same stream.
    pub async fn send(
        &self,
        address: &str,
        amount_sats: u64,
        renewal: Option<Renewal>,
    ) -> Result<Sent> {
        let (info, wire) = self.info().await?;
        let held = self.held(&info).await?;
        let mut out = Outbox::<SendClientMsg>::new();
        out.say(send_client_msg::Body::Open(SendOpen {
            recipient_ark_address: address.to_string(),
            amount: amount_sats,
            ark_info: Some(wire.clone()),
            vtxos: held.iter().map(wire_vtxo).collect(),
            identifier: self.identifier(),
        }))
        .await?;
        let mut guest = guest(&self.enclave, &self.client, "Send").await?;
        let mut inbound = guest
            .send(out.stream())
            .await
            .map_err(|s| status("Send", s))?
            .into_inner();

        let sighashes = match next_send(&mut inbound).await? {
            send_server_msg::Body::Sighashes(s) if s.exit_messages.is_empty() => s,
            other => return Err(unexpected("Send", "its sighashes", &other)),
        };
        let rounds = self.sign(
            &sighashes.cosigner_identifier,
            &sighashes.messages_to_sign,
            &sighashes.cosigner_commitments,
        )?;
        out.say(send_client_msg::Body::Signed(SendSigned { rounds }))
            .await?;

        let submit = match next_send(&mut inbound).await? {
            send_server_msg::Body::Submit(s) => s,
            other => return Err(unexpected("Send", "what to submit", &other)),
        };
        let submitted = self
            .asp
            .submit_tx(submit.ark_tx_b64, submit.checkpoint_txs)
            .await?;
        out.say(send_client_msg::Body::Submitted(SendSubmitted {
            ark_txid: submitted.ark_txid.clone(),
            signed_checkpoint_txs: submitted.signed_checkpoint_txs,
        }))
        .await?;

        let finalize = match next_send(&mut inbound).await? {
            send_server_msg::Body::Finalize(f) => f,
            other => return Err(unexpected("Send", "what to finalize", &other)),
        };
        self.asp
            .finalize_tx(finalize.ark_txid, finalize.final_checkpoint_txs)
            .await?;
        out.say(send_client_msg::Body::Finalized(SendFinalized {}))
            .await?;

        let complete = match next_send(&mut inbound).await? {
            send_server_msg::Body::Complete(c) => c,
            other => return Err(unexpected("Send", "its completion", &other)),
        };

        let renewed = match renewal {
            None => None,
            Some(renewal) => {
                let spent: Vec<(String, u32)> =
                    held.iter().map(|v| (v.txid.clone(), v.vout)).collect();
                let now = self
                    .held_once(&info, |h| {
                        !h.iter().any(|v| spent.contains(&(v.txid.clone(), v.vout)))
                    })
                    .await?;
                let (request, plan) = self.delegate_request(&info, &wire, &now, &renewal)?;
                out.say(send_client_msg::Body::RenewDelegate(request))
                    .await?;
                let sighashes = match next_send(&mut inbound).await? {
                    send_server_msg::Body::Sighashes(s) => s,
                    other => return Err(unexpected("Send", "the delegate's sighashes", &other)),
                };
                let rounds = self.delegate_rounds(
                    &plan,
                    &sighashes.messages_to_sign,
                    &sighashes.exit_messages,
                    &sighashes.cosigner_identifier,
                    &sighashes.cosigner_commitments,
                )?;
                out.say(send_client_msg::Body::Signed(SendSigned { rounds }))
                    .await?;
                match next_send(&mut inbound).await? {
                    send_server_msg::Body::DelegateRenewed(d) => Some(renewed(&plan, d)?),
                    other => return Err(unexpected("Send", "the renewed delegate", &other)),
                }
            }
        };
        Ok(Sent {
            ark_txid: complete.ark_txid,
            renewed,
        })
    }

    /// Bring the on-chain output `(txid, vout, amount_sats)`, paid to [`Self::boarding_address`],
    /// into Ark.
    pub async fn board(
        &self,
        utxo: (String, u32, u64),
        renewal: Option<Renewal>,
    ) -> Result<Settled> {
        let (info, wire) = self.info().await?;
        let (txid, vout, amount_sats) = utxo;
        let open = renew_client_msg::Body::Board(BoardOpen {
            utxo: Some(BoardingUtxo {
                txid,
                vout,
                amount_sats,
            }),
            ark_info: Some(wire.clone()),
            identifier: self.identifier(),
        });
        self.round("Board", open, &info, &wire, renewal).await
    }

    /// Refresh everything held into a new VTXO now, in the next round.
    pub async fn refresh(&self, renewal: Option<Renewal>) -> Result<Settled> {
        let (info, wire) = self.info().await?;
        let held = self.held(&info).await?;
        if held.is_empty() {
            return Err(Error::Protocol("nothing is held to refresh".into()));
        }
        let open = renew_client_msg::Body::Open(RenewOpen {
            ark_info: Some(wire.clone()),
            vtxos: held.iter().map(wire_vtxo).collect(),
            identifier: self.identifier(),
            ..Default::default()
        });
        self.round("Renew", open, &info, &wire, renewal).await
    }

    /// Renew only the delegate over what is held, and its exits: the guest refreshes these VTXOs
    /// itself before they expire, with nobody connected.
    pub async fn protect(&self, renewal: Renewal) -> Result<Renewed> {
        let (info, wire) = self.info().await?;
        let held = self.held(&info).await?;
        let (request, plan) = self.delegate_request(&info, &wire, &held, &renewal)?;
        let mut out = Outbox::<RenewClientMsg>::new();
        out.say(renew_client_msg::Body::Open(RenewOpen {
            ark_info: request.ark_info,
            vtxos: request.vtxos,
            delegate_only: true,
            device_token: request.device_token,
            exit_script_pubkey: request.exit_script_pubkey,
            identifier: self.identifier(),
        }))
        .await?;
        let mut guest = guest(&self.enclave, &self.client, "Renew").await?;
        let mut inbound = guest
            .renew(out.stream())
            .await
            .map_err(|s| status("Renew", s))?
            .into_inner();
        let sighashes = match next_renew(&mut inbound).await? {
            renew_server_msg::Body::Sighashes(s) => s,
            other => return Err(unexpected("Renew", "the delegate's sighashes", &other)),
        };
        let rounds = self.delegate_rounds(
            &plan,
            &sighashes.messages_to_sign,
            &sighashes.exit_messages,
            &sighashes.cosigner_identifier,
            &sighashes.cosigner_commitments,
        )?;
        out.say(renew_client_msg::Body::Signed(RenewSigned { rounds }))
            .await?;
        match next_renew(&mut inbound).await? {
            renew_server_msg::Body::DelegateRenewed(d) => renewed(&plan, d),
            other => Err(unexpected("Renew", "the renewed delegate", &other)),
        }
    }

    /// The round `board` and `refresh` share: the guest's sighashes signed, its intent registered,
    /// and every ASP event relayed to it until it settles; then, if asked, the delegate renewed.
    async fn round(
        &self,
        method: &str,
        open: renew_client_msg::Body,
        info: &Info,
        wire: &WireInfo,
        renewal: Option<Renewal>,
    ) -> Result<Settled> {
        let mut out = Outbox::<RenewClientMsg>::new();
        out.say(open).await?;
        let mut guest = guest(&self.enclave, &self.client, method).await?;
        let response = if method == "Board" {
            guest.board(out.stream()).await
        } else {
            guest.renew(out.stream()).await
        };
        let mut inbound = response.map_err(|s| status(method, s))?.into_inner();

        let mut events = None;
        let mut settled: Option<Settled> = None;
        let mut plan: Option<Plan> = None;
        loop {
            match next_renew(&mut inbound).await? {
                renew_server_msg::Body::Sighashes(s) => {
                    let rounds = match &plan {
                        Some(plan) => self.delegate_rounds(
                            plan,
                            &s.messages_to_sign,
                            &s.exit_messages,
                            &s.cosigner_identifier,
                            &s.cosigner_commitments,
                        )?,
                        None if s.exit_messages.is_empty() => self.sign(
                            &s.cosigner_identifier,
                            &s.messages_to_sign,
                            &s.cosigner_commitments,
                        )?,
                        None => {
                            return Err(Error::Protocol(
                                "exits offered with no delegate asked for".into(),
                            ))
                        }
                    };
                    out.say(renew_client_msg::Body::Signed(RenewSigned { rounds }))
                        .await?;
                }
                renew_server_msg::Body::Register(r) => {
                    events = Some(self.asp.events(r.topics).await?);
                    let intent_id = self.asp.register_intent(r.proof, r.message).await?;
                    out.say(renew_client_msg::Body::Registered(IntentRegistered {
                        intent_id,
                    }))
                    .await?;
                }
                renew_server_msg::Body::Submit(call) => {
                    self.asp.submit(call).await?;
                    out.say(relay(&mut events).await?).await?;
                }
                renew_server_msg::Body::Idle(_) => {
                    out.say(relay(&mut events).await?).await?;
                }
                renew_server_msg::Body::Complete(c) => {
                    let mut done = Settled {
                        commitment_txid: c.commitment_txid,
                        vtxo_txid: c.vtxo_txid,
                        vtxo_vout: c.vtxo_vout,
                        amount_sats: c.amount_sats,
                        exit_delay: c.exit_delay,
                        renewed: None,
                    };
                    // The guest reports no amount for a refresh: the indexer has it, as it has
                    // the set a delegate renewed now must cover.
                    if done.amount_sats != 0 && renewal.is_none() {
                        return Ok(done);
                    }
                    let new = (done.vtxo_txid.clone(), done.vtxo_vout);
                    let is_new = |v: &Vtxo| (v.txid.clone(), v.vout) == new;
                    let now = self.held_once(info, |h| h.iter().any(is_new)).await?;
                    if done.amount_sats == 0 {
                        done.amount_sats =
                            now.iter().find(|v| is_new(v)).map_or(0, |v| v.amount_sats);
                    }
                    let Some(renewal) = &renewal else {
                        return Ok(done);
                    };
                    let (request, p) = self.delegate_request(info, wire, &now, renewal)?;
                    plan = Some(p);
                    out.say(renew_client_msg::Body::RenewDelegate(request))
                        .await?;
                    settled = Some(done);
                }
                renew_server_msg::Body::DelegateRenewed(d) => {
                    let plan = plan.as_ref().ok_or_else(|| {
                        Error::Protocol("a delegate renewed that was not asked for".into())
                    })?;
                    let mut done = settled.take().ok_or_else(|| {
                        Error::Protocol("a delegate renewed before the round settled".into())
                    })?;
                    done.renewed = Some(renewed(plan, d)?);
                    return Ok(done);
                }
            }
        }
    }

    fn delegate_request(
        &self,
        info: &Info,
        wire: &WireInfo,
        held: &[Vtxo],
        renewal: &Renewal,
    ) -> Result<(RenewDelegate, Plan)> {
        let vtxos: Vec<VtxoInput> = held.iter().map(wire_vtxo).collect();
        let destination = self.exit_script(info, renewal)?;
        let plan = if destination.is_empty() {
            Plan::new(info, self.owner(), &[], &destination)
        } else {
            Plan::new(info, self.owner(), &vtxos, &destination)
        };
        Ok((
            RenewDelegate {
                vtxos,
                ark_info: Some(wire.clone()),
                device_token: renewal.device_token.clone().unwrap_or_default(),
                exit_script_pubkey: destination.to_bytes(),
            },
            plan,
        ))
    }

    /// The delegate's round: its messages, then the exits', which must be exactly the ones
    /// [`Plan`] built.
    fn delegate_rounds(
        &self,
        plan: &Plan,
        delegate: &[Vec<u8>],
        exits: &[Vec<u8>],
        cosigner: &str,
        commitments: &[crate::proto::guest::Commitment],
    ) -> Result<Vec<WalletRound>> {
        plan.check(exits)?;
        let messages: Vec<Vec<u8>> = delegate.iter().chain(exits).cloned().collect();
        self.sign(cosigner, &messages, commitments)
    }
}

fn renewed(plan: &Plan, d: DelegateRenewed) -> Result<Renewed> {
    Ok(Renewed {
        valid_at_secs: d.valid_at_secs,
        margin_secs: d.margin_secs,
        covered: d.covered,
        device_enrolled: d.device_enrolled,
        exits: plan.verify(&d.exit_txs)?,
    })
}

fn wire_vtxo(v: &Vtxo) -> VtxoInput {
    VtxoInput {
        txid: v.txid.clone(),
        vout: v.vout,
        amount_sats: v.amount_sats,
        exit_delay: v.exit_delay,
        expires_at: v.expires_at,
    }
}

/// The next ASP event, for the guest.
async fn relay(
    events: &mut Option<Streaming<ark::client::proto::GetEventStreamResponse>>,
) -> Result<renew_client_msg::Body> {
    let events = events
        .as_mut()
        .ok_or_else(|| Error::Protocol("the guest waits on an event before any intent".into()))?;
    let event = events
        .message()
        .await
        .map_err(|s| Error::Asp(format!("the event stream: {}", s.message())))?
        .ok_or_else(|| Error::Asp("the event stream ended mid-round".into()))?;
    Ok(renew_client_msg::Body::Event(AspEvent {
        encoded: event.encode_to_vec(),
    }))
}

async fn next_send(inbound: &mut Streaming<SendServerMsg>) -> Result<send_server_msg::Body> {
    inbound
        .message()
        .await
        .map_err(|s| status("Send", s))?
        .and_then(|m| m.body)
        .ok_or_else(|| Error::Enclave("Send: the guest closed the stream".into()))
}

async fn next_renew(inbound: &mut Streaming<RenewServerMsg>) -> Result<renew_server_msg::Body> {
    inbound
        .message()
        .await
        .map_err(|s| status("Renew", s))?
        .and_then(|m| m.body)
        .ok_or_else(|| Error::Enclave("Renew: the guest closed the stream".into()))
}

fn unexpected(call: &str, wanted: &str, got: &impl std::fmt::Debug) -> Error {
    let got = format!("{got:?}");
    let got = got
        .split(['(', ' ', '{'])
        .next()
        .unwrap_or_default()
        .to_string();
    Error::Protocol(format!("{call}: expected {wanted}, the guest sent {got}"))
}

/// The phone's side of a stream: messages numbered in order, under one session id.
struct Outbox<M> {
    tx: mpsc::Sender<M>,
    rx: Option<mpsc::Receiver<M>>,
    session: String,
    seq: u64,
}

trait Envelope<B> {
    fn wrap(session_id: String, seq: u64, body: B) -> Self;
}

impl Envelope<send_client_msg::Body> for SendClientMsg {
    fn wrap(session_id: String, seq: u64, body: send_client_msg::Body) -> Self {
        SendClientMsg {
            session_id,
            seq,
            body: Some(body),
        }
    }
}

impl Envelope<renew_client_msg::Body> for RenewClientMsg {
    fn wrap(session_id: String, seq: u64, body: renew_client_msg::Body) -> Self {
        RenewClientMsg {
            session_id,
            seq,
            body: Some(body),
        }
    }
}

impl<M> Outbox<M> {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel(16);
        let mut id = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        Outbox {
            tx,
            rx: Some(rx),
            session: hex::encode(id),
            seq: 0,
        }
    }

    async fn say<B>(&mut self, body: B) -> Result<()>
    where
        M: Envelope<B>,
    {
        self.seq += 1;
        self.tx
            .send(M::wrap(self.session.clone(), self.seq, body))
            .await
            .map_err(|_| Error::Transport("the stream to the guest closed".into()))
    }

    /// What tonic sends: everything said, until this outbox is dropped.
    fn stream(&mut self) -> ReceiverStream<M> {
        ReceiverStream::new(self.rx.take().expect("a stream is opened once"))
    }
}
