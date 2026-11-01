//! The half of the wallet's share the cosigner dealt, handed back on the streams that sign.
//!
//! The wallet keeps no share between operations. Each one re-derives the wallet's own half from its
//! passkey and adds the half the cosigner dealt it at DKG — which the runtime recomputes, and which
//! rides the first round of `Sign`, `Send`, `Renew` and `Board`, under the approval the stream
//! already has. These tests are about what may come back, to whom, and how often:
//!
//!  * to the identifier the wallet key records, and to no other;
//!  * once per stream, on its first round;
//!  * and never the cosigner's *own* share, which is a different scalar and leaves for nobody.
//!
//! On tenants. One tenant is one instance over one store; the runtime scopes the filesystem and
//! this component never sees another tenant's seal. There is no in-guest tenant table to test, so
//! "tenant A cannot read tenant B's half" is shown the only way it can be here: two instances over
//! two stores, each asked with the other's wallet, each refusing.
//!
//! Driven through `route`, over real frames, because the property is about the wire. A body is
//! written whole before the handler runs, so a test reads what the cosigner says first and cannot
//! answer it — the stream then ends `Cancelled`, which is what a wallet vanishing looks like.

mod common;

use cosigner::grpc::Code;
use cosigner::session::proto;
use cosigner::wallet_proto as wp;
use cosigner::Cosigner;

use common::wire::{block_on, collect, request, service, Answer};

/// The ASP's key in `ark_info()`: the secp256k1 generator's x, a valid x-only key.
const ASP_XONLY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

struct Wallet {
    cosigner: Cosigner,
    test: common::TestWallet,
}

impl Wallet {
    fn identifier(&self) -> Vec<u8> {
        self.test.user.identifier.serialize().to_vec()
    }
}

/// A wallet in its own store — its own tenant — whose runtime holds its key.
fn wallet() -> Option<Wallet> {
    let store = common::try_store()?;
    let test = common::wallet();
    let cosigner = common::open_holding(&store, &test);
    Some(Wallet { cosigner: cosigner.into_inner().unwrap(), test })
}

fn ark_info() -> wp::ArkInfo {
    wp::ArkInfo {
        signer_pubkey: ASP_XONLY.into(),
        forfeit_pubkey: format!("02{ASP_XONLY}"),
        forfeit_address: "bcrt1qq5rjlmqartxjyh6vnmjrhrqnc58q2hqr5asln0".into(),
        checkpoint_tapscript: String::new(),
        network: "regtest".into(),
        session_duration: 0,
        unilateral_exit_delay: 512,
        boarding_exit_delay: 144,
        vtxo_min_amount: 0,
        dust: 330,
    }
}

fn vtxo(txid: char) -> proto::VtxoInput {
    proto::VtxoInput {
        txid: txid.to_string().repeat(64),
        vout: 0,
        amount_sats: 50_000,
        exit_delay: 512,
        // A delegate needs a deadline to be scheduled against.
        expires_at: 4_102_444_800,
    }
}

fn sign_open(identifier: Vec<u8>) -> proto::SignClientMsg {
    proto::SignClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::sign_client_msg::Body::Open(proto::SignOpen {
            message_to_sign: vec![0x42; 32],
            full_transaction: Vec::new(),
            script_path_spend: true,
            identifier,
        })),
    }
}

/// A send to the wallet's own Ark address: somewhere real to pay, with nothing else to set up.
fn send_open(w: &Wallet, identifier: Vec<u8>) -> proto::SendClientMsg {
    let owner = hex::encode(&w.test.key.group_key()[1..]);
    let recipient =
        ark::client::address::ark_address(&owner, ASP_XONLY, 512, bitcoin::Network::Regtest)
            .expect("an Ark address");
    proto::SendClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::send_client_msg::Body::Open(proto::SendOpen {
            recipient_ark_address: recipient,
            amount: 10_000,
            ark_info: Some(ark_info()),
            vtxos: vec![vtxo('a')],
            identifier,
            ..Default::default()
        })),
    }
}

/// A `delegate_only` renewal: the one renewal whose first round needs no ASP to have said anything.
fn renew_open(identifier: Vec<u8>) -> proto::RenewClientMsg {
    proto::RenewClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::renew_client_msg::Body::Open(proto::RenewOpen {
            ark_info: Some(ark_info()),
            vtxos: vec![vtxo('a')],
            delegate_only: true,
            identifier,
            ..Default::default()
        })),
    }
}

/// The dealt share on a stream's first answer, whichever stream it is.
enum First {
    Sign(Answer<proto::SignServerMsg>),
    Send(Answer<proto::SendServerMsg>),
    Renew(Answer<proto::RenewServerMsg>),
}

impl First {
    fn code(&self) -> u32 {
        match self {
            First::Sign(a) => a.code,
            First::Send(a) => a.code,
            First::Renew(a) => a.code,
        }
    }

    fn message(&self) -> &str {
        match self {
            First::Sign(a) => &a.message,
            First::Send(a) => &a.message,
            First::Renew(a) => &a.message,
        }
    }

    fn answered(&self) -> usize {
        match self {
            First::Sign(a) => a.messages.len(),
            First::Send(a) => a.messages.len(),
            First::Renew(a) => a.messages.len(),
        }
    }

    /// What the first answer carried as the wallet's dealt share. Panics if there was no answer, or
    /// it was not the round that carries one.
    fn dealt(&self) -> Vec<u8> {
        match self {
            First::Sign(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::sign_server_msg::Body::Commitments(c)) => c.wallet_dealt_share.clone(),
                other => panic!("expected the commitments round, got {other:?}"),
            },
            First::Send(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::send_server_msg::Body::Sighashes(s)) => s.wallet_dealt_share.clone(),
                other => panic!("expected sighashes, got {other:?}"),
            },
            First::Renew(a) => match &a.messages.first().expect("an answer").body {
                Some(proto::renew_server_msg::Body::Sighashes(s)) => s.wallet_dealt_share.clone(),
                other => panic!("expected sighashes, got {other:?}"),
            },
        }
    }
}

const STREAMS: &[&str] = &["Sign", "Send", "Renew", "Board"];

/// A boarding of one on-chain output: its first round is the intent proof, which needs no ASP.
fn board_open(identifier: Vec<u8>) -> proto::RenewClientMsg {
    proto::RenewClientMsg {
        session_id: "s".into(),
        seq: 0,
        body: Some(proto::renew_client_msg::Body::Board(proto::BoardOpen {
            utxo: Some(proto::BoardingUtxo { txid: "b".repeat(64), vout: 0, amount_sats: 50_000 }),
            ark_info: Some(ark_info()),
            identifier,
        })),
    }
}

/// Open [stream] on [w]'s instance as the wallet [identifier] claims to be, and read what comes back.
fn open(stream: &str, w: Wallet, identifier: Vec<u8>) -> First {
    match stream {
        "Sign" => First::Sign(collect(block_on(
            service(w.cosigner).route(request("Sign", &[sign_open(identifier)])),
        ))),
        "Send" => {
            let open = send_open(&w, identifier);
            First::Send(collect(block_on(
                service(w.cosigner).route(request("Send", &[open])),
            )))
        }
        "Renew" => First::Renew(collect(block_on(
            service(w.cosigner).route(request("Renew", &[renew_open(identifier)])),
        ))),
        // `Board` speaks `Renew`'s messages; only its open differs.
        "Board" => First::Renew(collect(block_on(
            service(w.cosigner).route(request("Board", &[board_open(identifier)])),
        ))),
        other => panic!("no such stream: {other}"),
    }
}

/// The wallet's own identifier gets the half it was dealt, verbatim, on the first round.
#[test]
fn every_signing_stream_returns_the_dealt_share_to_the_wallets_own_identifier() {
    for stream in STREAMS {
        let Some(w) = wallet() else { return };
        let (id, dealt) = (w.identifier(), w.test.dealt_share());
        let first = open(stream, w, id);
        assert_eq!(
            first.answered(),
            1,
            "{stream}: one round went out before the client vanished ({} {})",
            first.code(),
            first.message()
        );
        assert_eq!(first.dealt(), dealt, "{stream}: the share the runtime recomputes");
        // The test cannot answer the round, so the stream is cut off — not failed, and not done.
        assert_eq!(first.code(), Code::Cancelled as u32, "{stream}: {}", first.message());
    }
}

/// What comes back is what the cosigner DEALT, never what it HOLDS. They are different scalars, and
/// the second one signs.
#[test]
fn the_cosigners_own_share_never_leaves() {
    for stream in STREAMS {
        let Some(w) = wallet() else { return };
        // The cosigner's share, as the runtime holds it.
        let own = threshold::scalar::scalar_to_bytes(&w.test.key.key_package.secret_share).to_vec();
        let id = w.identifier();
        let dealt = open(stream, w, id).dealt();
        assert_ne!(dealt, own, "{stream} returned the cosigner's own signing share");
    }
}

/// A wallet that is not this one — a wrong passkey, a PRF that answers differently, or somebody
/// else's wallet altogether — is refused, and before anything is said.
#[test]
fn an_identifier_the_ceremony_never_saw_is_refused_on_every_stream() {
    for stream in STREAMS {
        let Some(w) = wallet() else { return };
        let Some(stranger) = wallet() else { return };
        let first = open(stream, w, stranger.identifier());
        assert_eq!(
            first.code(),
            Code::PermissionDenied as u32,
            "{stream}: {}",
            first.message()
        );
        assert_eq!(first.answered(), 0, "{stream} answered a wallet that is not its own");
    }
}

/// Two tenants are two instances over two stores. Each holds one wallet's half and refuses the
/// other's wallet — and neither can be made to say what the other holds.
#[test]
fn one_tenants_instance_does_not_answer_for_another_tenants_wallet() {
    for stream in STREAMS {
        let (Some(a), Some(b)) = (wallet(), wallet()) else {
            return;
        };
        let (id_a, id_b) = (a.identifier(), b.identifier());

        let b_on_a = open(stream, a, id_b);
        assert_eq!(b_on_a.code(), Code::PermissionDenied as u32, "{stream}: {}", b_on_a.message());
        assert_eq!(b_on_a.answered(), 0);

        let a_on_b = open(stream, b, id_a);
        assert_eq!(a_on_b.code(), Code::PermissionDenied as u32, "{stream}: {}", a_on_b.message());
        assert_eq!(a_on_b.answered(), 0);
    }
}

/// An identifier that is not 32 bytes — or not sent, which is what a wallet from before this would
/// do — is a malformed request, not a wrong passkey.
#[test]
fn a_missing_identifier_is_refused() {
    for stream in STREAMS {
        let Some(w) = wallet() else { return };
        let first = open(stream, w, Vec::new());
        assert_eq!(first.code(), Code::InvalidArgument as u32, "{stream}: {}", first.message());
        assert_eq!(first.answered(), 0);
    }
}

/// A tenant whose runtime holds no wallet key has nothing to sign with, and says so before
/// anything goes out.
#[test]
fn a_tenant_with_no_wallet_key_cannot_sign() {
    for stream in STREAMS {
        let Some(store) = common::try_store() else { return };
        let test = common::wallet();
        let cosigner = common::open_cosigner(&store, &test.group_key()).into_inner().unwrap();
        let w = Wallet { cosigner, test };
        let id = w.identifier();
        let first = open(stream, w, id);
        assert_eq!(first.code(), Code::FailedPrecondition as u32, "{stream}: {}", first.message());
        assert!(first.message().contains("has no key"), "{stream}: {}", first.message());
        assert_eq!(first.answered(), 0);
    }
}

/// `Sign` is script-path only, and says so rather than failing later as a bad share.
#[test]
fn a_key_path_sign_is_refused_by_name() {
    let Some(w) = wallet() else { return };
    let mut open = sign_open(w.identifier());
    if let Some(proto::sign_client_msg::Body::Open(o)) = &mut open.body {
        o.script_path_spend = false;
    }
    let answer = collect::<proto::SignServerMsg>(block_on(
        service(w.cosigner).route(request("Sign", &[open])),
    ));
    assert_eq!(answer.code, Code::InvalidArgument as u32, "{}", answer.message);
    assert!(answer.messages.is_empty(), "no share may go out for a round that will not run");
}
