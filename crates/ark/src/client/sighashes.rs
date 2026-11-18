//! Signing through ark-core's own helpers when the signature is made somewhere else.
//!
//! ark-core signs inside a closure it calls while it works, and the wallet key's signature is a
//! FROST round over the network, which no closure can wait for. So each helper runs twice over the
//! same transaction: once on a copy, with [`Collect`] noting every message the helper asks to have
//! signed — those are the sighashes handed out — and then, when the signatures are back, on the
//! real transaction, with [`Replay`] answering each message in the order it was noted.
//!
//! That is sound because the helpers use no randomness and read no clock: the second run asks for
//! exactly what the first one noted. [`Replay`] refuses anything else, so a transaction that
//! changed between the runs is an error rather than a signature over something nobody saw.

use std::cell::{Cell, RefCell};

use ark_core::Error;
use bitcoin::psbt;
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::XOnlyPublicKey;

/// What ark-core's helpers that take any number of signatures expect back.
type Signatures = Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, Error>;

/// Pass one: notes each message, signs nothing.
#[derive(Default)]
pub(crate) struct Collect(RefCell<Vec<[u8; 32]>>);

impl Collect {
    /// For helpers that take any number of signatures: none, so nothing is inserted.
    pub(crate) fn any(&self) -> impl Fn(&mut psbt::Input, Message) -> Signatures + '_ {
        move |_, msg| {
            self.note(&msg);
            Ok(Vec::new())
        }
    }

    /// For `make_intent`'s on-chain inputs, which must have exactly one: a placeholder, which
    /// `make_intent` does not check and which is thrown away with the copy.
    pub(crate) fn one(
        &self,
        owner: XOnlyPublicKey,
    ) -> impl Fn(&mut psbt::Input, Message) -> Result<(schnorr::Signature, XOnlyPublicKey), Error> + '_
    {
        move |_, msg| {
            self.note(&msg);
            let placeholder = schnorr::Signature::from_slice(&[0; 64]).expect("64 bytes");
            Ok((placeholder, owner))
        }
    }

    /// For `sign_commitment_psbt`, which verifies what it is given: note the message, then stop
    /// it there. It signs one input per call, so the caller makes one call per input.
    pub(crate) fn checked(
        &self,
    ) -> impl Fn(&XOnlyPublicKey, &Message) -> Result<schnorr::Signature, Error> + '_ {
        move |_, msg| {
            self.note(msg);
            Err(Error::ad_hoc("collected"))
        }
    }

    fn note(&self, msg: &Message) {
        self.0.borrow_mut().push(*msg.as_ref());
    }

    pub(crate) fn len(&self) -> usize {
        self.0.borrow().len()
    }

    pub(crate) fn into_messages(self) -> Vec<[u8; 32]> {
        self.0.into_inner()
    }
}

/// Pass two: answers each message with its signature, in the order pass one noted them.
pub(crate) struct Replay {
    messages: Vec<[u8; 32]>,
    signatures: Vec<schnorr::Signature>,
    owner: XOnlyPublicKey,
    next: Cell<usize>,
}

impl Replay {
    /// `signatures[i]` is the wallet key's signature over `messages[i]`.
    pub(crate) fn new(
        messages: &[[u8; 32]],
        signatures: &[[u8; 64]],
        owner: XOnlyPublicKey,
    ) -> Result<Self, String> {
        if signatures.len() != messages.len() {
            return Err(format!(
                "expected {} signatures, got {}",
                messages.len(),
                signatures.len()
            ));
        }
        let signatures = signatures
            .iter()
            .map(|s| {
                schnorr::Signature::from_slice(s).map_err(|e| format!("invalid schnorr sig: {e}"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            messages: messages.to_vec(),
            signatures,
            owner,
            next: Cell::new(0),
        })
    }

    fn answer(&self, msg: &Message) -> Result<schnorr::Signature, Error> {
        let i = self.next.get();
        match self.messages.get(i) {
            Some(expected) if expected == msg.as_ref() => {
                self.next.set(i + 1);
                Ok(self.signatures[i])
            }
            Some(_) => Err(Error::ad_hoc(format!(
                "message {i} is not the one that was signed"
            ))),
            None => Err(Error::ad_hoc(format!(
                "asked for a signature beyond the {} signed",
                self.messages.len()
            ))),
        }
    }

    /// For helpers that take any number of signatures: the owner's.
    pub(crate) fn any(&self) -> impl Fn(&mut psbt::Input, Message) -> Signatures + '_ {
        move |_, msg| Ok(vec![(self.answer(&msg)?, self.owner)])
    }

    /// For `make_intent`'s on-chain inputs.
    pub(crate) fn one(
        &self,
    ) -> impl Fn(&mut psbt::Input, Message) -> Result<(schnorr::Signature, XOnlyPublicKey), Error> + '_
    {
        move |_, msg| Ok((self.answer(&msg)?, self.owner))
    }

    /// For `sign_commitment_psbt`, which then verifies the signature against the input's key.
    pub(crate) fn checked(
        &self,
    ) -> impl Fn(&XOnlyPublicKey, &Message) -> Result<schnorr::Signature, Error> + '_ {
        move |_, msg| self.answer(msg)
    }

    /// Every signature was asked for: a run that asked for fewer than were made signed less than
    /// the wallet approved.
    pub(crate) fn finish(&self) -> Result<(), String> {
        let used = self.next.get();
        if used == self.messages.len() {
            Ok(())
        } else {
            Err(format!("{used} of {} signatures were used", self.messages.len()))
        }
    }
}
