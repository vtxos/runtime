//! The ASP: arkd's `ArkService` and `IndexerService`, over HTTP/2.
//!
//! The guest never reaches the ASP during a ceremony; the phone does, and relays what the ASP says.
//! So these are the calls the ceremonies need, the indexer's VTXO listing, and the chains of
//! virtual transactions an exit needs on chain before it.

use ark::client::proto::{
    ConfirmRegistrationRequest, FinalizeTxRequest, GetEventStreamRequest, GetEventStreamResponse,
    GetInfoRequest, GetInfoResponse, GetVirtualTxsRequest, GetVtxoChainRequest, GetVtxosRequest,
    IndexerChain, IndexerOutpoint, IndexerPageRequest, IndexerPageResponse, IndexerVtxo, Intent,
    RegisterIntentRequest, SubmitSignedForfeitTxsRequest, SubmitTreeNoncesRequest,
    SubmitTreeSignaturesRequest, SubmitTxRequest, SubmitTxResponse,
};
use http::Uri;
use hyper::client::conn::http2::SendRequest;
use tokio::sync::Mutex;
use tonic::body::BoxBody;
use tonic::Streaming;

use crate::error::{Error, Result};
use crate::h2::{connect_public, Channel};
use crate::proto::arkd::ark_service_client::ArkServiceClient;
use crate::proto::arkd::indexer_service_client::IndexerServiceClient;
use crate::proto::guest::{asp_submit, AspSubmit};

/// An ASP, by URL. Connects lazily and reconnects when the connection drops.
pub struct Asp {
    url: String,
    connection: Mutex<Option<(SendRequest<BoxBody>, Uri)>>,
}

/// The indexer's pages, as the Arkade SDK walks them.
const PAGE_SIZE: i32 = 100;

/// The index of the page after `page`, if there is one.
fn next_page(page: Option<IndexerPageResponse>, items: usize) -> Option<i32> {
    let page = page?;
    (page.current < page.total && items >= PAGE_SIZE as usize).then_some(page.next)
}

fn refused(call: &str, status: tonic::Status) -> Error {
    Error::Asp(format!(
        "{call}: {} ({:?})",
        status.message(),
        status.code()
    ))
}

impl Asp {
    /// `url` is `https://host[:port]`, or `http://` for a regtest ASP.
    pub fn new(url: &str) -> Self {
        Asp {
            url: url.to_string(),
            connection: Mutex::new(None),
        }
    }

    async fn channel(&self) -> Result<(Channel, Uri)> {
        let mut slot = self.connection.lock().await;
        if let Some((send, origin)) = slot.as_ref().filter(|(send, _)| !send.is_closed()) {
            return Ok((Channel::new(send.clone(), None), origin.clone()));
        }
        let (send, origin) = connect_public(&self.url)
            .await
            .map_err(|e| Error::Asp(e.to_string()))?;
        *slot = Some((send.clone(), origin.clone()));
        Ok((Channel::new(send, None), origin))
    }

    async fn ark(&self) -> Result<ArkServiceClient<Channel>> {
        let (channel, origin) = self.channel().await?;
        Ok(ArkServiceClient::with_origin(channel, origin))
    }

    async fn indexer(&self) -> Result<IndexerServiceClient<Channel>> {
        let (channel, origin) = self.channel().await?;
        Ok(IndexerServiceClient::with_origin(channel, origin))
    }

    pub async fn info(&self) -> Result<GetInfoResponse> {
        Ok(self
            .ark()
            .await?
            .get_info(GetInfoRequest {})
            .await
            .map_err(|s| refused("GetInfo", s))?
            .into_inner())
    }

    /// The spendable VTXOs under `script` (hex).
    pub async fn vtxos(&self, script: &str) -> Result<Vec<IndexerVtxo>> {
        Ok(self
            .indexer()
            .await?
            .get_vtxos(GetVtxosRequest {
                scripts: vec![script.to_string()],
                spendable_only: true,
                ..Default::default()
            })
            .await
            .map_err(|s| refused("GetVtxos", s))?
            .into_inner()
            .vtxos)
    }

    /// The transactions a VTXO descends from, back to the commitment transactions it comes out of.
    pub async fn vtxo_chain(&self, txid: &str, vout: u32) -> Result<Vec<IndexerChain>> {
        let mut indexer = self.indexer().await?;
        let mut chain = Vec::new();
        let mut index = Some(0);
        while let Some(i) = index {
            let answer = indexer
                .get_vtxo_chain(GetVtxoChainRequest {
                    outpoint: Some(IndexerOutpoint {
                        txid: txid.to_string(),
                        vout,
                    }),
                    page: Some(IndexerPageRequest {
                        size: PAGE_SIZE,
                        index: i,
                    }),
                })
                .await
                .map_err(|s| refused("GetVtxoChain", s))?
                .into_inner();
            index = next_page(answer.page, answer.chain.len());
            chain.extend(answer.chain);
        }
        Ok(chain)
    }

    /// The virtual transactions `txids`, as signed PSBTs in base64.
    pub async fn virtual_txs(&self, txids: &[String]) -> Result<Vec<String>> {
        let mut indexer = self.indexer().await?;
        let mut txs = Vec::new();
        let mut index = Some(0);
        while let Some(i) = index {
            let answer = indexer
                .get_virtual_txs(GetVirtualTxsRequest {
                    txids: txids.to_vec(),
                    page: Some(IndexerPageRequest {
                        size: PAGE_SIZE,
                        index: i,
                    }),
                })
                .await
                .map_err(|s| refused("GetVirtualTxs", s))?
                .into_inner();
            index = next_page(answer.page, answer.txs.len());
            txs.extend(answer.txs);
        }
        Ok(txs)
    }

    pub async fn submit_tx(
        &self,
        signed_ark_tx: String,
        checkpoint_txs: Vec<String>,
    ) -> Result<SubmitTxResponse> {
        Ok(self
            .ark()
            .await?
            .submit_tx(SubmitTxRequest {
                signed_ark_tx,
                checkpoint_txs,
            })
            .await
            .map_err(|s| refused("SubmitTx", s))?
            .into_inner())
    }

    pub async fn finalize_tx(
        &self,
        ark_txid: String,
        final_checkpoint_txs: Vec<String>,
    ) -> Result<()> {
        self.ark()
            .await?
            .finalize_tx(FinalizeTxRequest {
                ark_txid,
                final_checkpoint_txs,
            })
            .await
            .map_err(|s| refused("FinalizeTx", s))?;
        Ok(())
    }

    /// The event stream for `topics`. Open it before registering, so no event of the round is
    /// missed.
    pub async fn events(&self, topics: Vec<String>) -> Result<Streaming<GetEventStreamResponse>> {
        Ok(self
            .ark()
            .await?
            .get_event_stream(GetEventStreamRequest { topics })
            .await
            .map_err(|s| refused("GetEventStream", s))?
            .into_inner())
    }

    pub async fn register_intent(&self, proof: String, message: String) -> Result<String> {
        Ok(self
            .ark()
            .await?
            .register_intent(RegisterIntentRequest {
                intent: Some(Intent { proof, message }),
            })
            .await
            .map_err(|s| refused("RegisterIntent", s))?
            .into_inner()
            .intent_id)
    }

    /// Make the call the guest asked for.
    pub async fn submit(&self, call: AspSubmit) -> Result<()> {
        let mut ark = self.ark().await?;
        match call.call {
            Some(asp_submit::Call::ConfirmRegistration(c)) => ark
                .confirm_registration(ConfirmRegistrationRequest {
                    intent_id: c.intent_id,
                })
                .await
                .map(drop)
                .map_err(|s| refused("ConfirmRegistration", s)),
            Some(asp_submit::Call::TreeNonces(n)) => ark
                .submit_tree_nonces(SubmitTreeNoncesRequest {
                    batch_id: n.batch_id,
                    pubkey: n.pubkey,
                    tree_nonces: n.nonces,
                })
                .await
                .map(drop)
                .map_err(|s| refused("SubmitTreeNonces", s)),
            Some(asp_submit::Call::TreeSignatures(t)) => ark
                .submit_tree_signatures(SubmitTreeSignaturesRequest {
                    batch_id: t.batch_id,
                    pubkey: t.pubkey,
                    tree_signatures: t.signatures,
                })
                .await
                .map(drop)
                .map_err(|s| refused("SubmitTreeSignatures", s)),
            Some(asp_submit::Call::ForfeitTxs(f)) => ark
                .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                    signed_forfeit_txs: f.signed_forfeit_txs,
                    signed_commitment_tx: f.signed_commitment_tx,
                })
                .await
                .map(drop)
                .map_err(|s| refused("SubmitSignedForfeitTxs", s)),
            None => Err(Error::Protocol("the guest asked for no call".into())),
        }
    }
}
