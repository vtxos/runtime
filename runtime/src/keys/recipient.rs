//! The one-boot key pair KMS encrypts its answer to, and the unwrapping of
//! that answer.
//!
//! `Decrypt` and `GenerateDataKey` normally return plaintext over the wire,
//! which inside an enclave would mean handing it to the parent — the party the
//! enclave exists to exclude, and the party that necessarily proxies the
//! request. The `Recipient` parameter is what avoids that: the caller supplies
//! an attestation document carrying a public key, KMS verifies the document
//! against the key policy, and encrypts its answer to that key instead.
//! `Plaintext` then comes back **absent**. The parent forwards bytes it cannot
//! open.
//!
//! ## The key pair
//!
//! Generated fresh for one boot, held only in enclave memory, and dropped
//! before anything is served. It is **transport plumbing**: it exists to carry
//! one 32-byte answer from KMS into this process, and it has nothing to do
//! with any key the guest signs with. Reusing it across boots, or persisting
//! it, would turn a value with a lifetime of milliseconds into one an attacker
//! has time to look for.
//!
//! ## The answer
//!
//! `CiphertextForRecipient` is a CMS `EnvelopedData` (RFC 5652): a
//! content-encryption key wrapped to our RSA public key, plus the content
//! encrypted under that key, sent as BER and rewritten to DER first
//! ([`ber_to_der`]). Parsing is the `cms` crate's job. **Deciding what
//! is acceptable is this module's job**, and it accepts exactly one shape —
//! one RSA-OAEP-SHA256 recipient, AES-256-CBC content, `id-data` inside
//! `id-envelopedData`. A general-purpose parser is fine; a general-purpose
//! *policy* on the path that unwraps the master key is not.

use anyhow::{bail, Context, Result};
use aws_lc_rs::cipher::{
    DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey, AES_256, AES_CBC_IV_LEN,
};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, PrivateDecryptingKey, OAEP_SHA256_MGF1SHA256,
};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientInfo};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};

/// `id-envelopedData` — the only CMS content type KMS returns here.
const ID_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");
/// `id-data` — the only content type we accept *inside* it.
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-RSAES-OAEP`, the key-transport algorithm. KMS documents
/// `RSAES_OAEP_SHA_256` as the only valid `KeyEncryptionMechanism`.
const ID_RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
/// `aes256-CBC`, the content-encryption algorithm.
const ID_AES_256_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42");

/// RSA-2048. KMS's own enclave SDK uses it, and the SPKI encoding is ~294
/// bytes — comfortably inside the NSM's limit on `public_key`, which a larger
/// modulus would approach for no benefit: this key protects one message with a
/// lifetime measured in milliseconds.
const RECIPIENT_KEY_SIZE: KeySize = KeySize::Rsa2048;

/// A key pair that exists for one KMS exchange.
pub struct RecipientKey {
    /// Built once, at generation. `OaepPrivateDecryptingKey::new` consumes the
    /// private key, so keeping the OAEP form is what avoids cloning key
    /// material on every use.
    oaep: OaepPrivateDecryptingKey,
    spki_der: Vec<u8>,
}

impl RecipientKey {
    pub fn generate() -> Result<Self> {
        let private = PrivateDecryptingKey::generate(RECIPIENT_KEY_SIZE)
            .map_err(|_| anyhow::anyhow!("generating the recipient key pair"))?;
        let spki_der = private
            .public_key()
            .as_der()
            .map_err(|_| anyhow::anyhow!("encoding the recipient public key"))?
            .as_ref()
            .to_vec();
        let oaep = OaepPrivateDecryptingKey::new(private)
            .map_err(|_| anyhow::anyhow!("preparing the recipient key for OAEP"))?;
        Ok(RecipientKey { oaep, spki_der })
    }

    /// The SPKI DER that goes into the attestation document's `public_key`.
    ///
    /// This is the whole binding: KMS checks the document against the key
    /// policy, then encrypts to the key the document carries. A document
    /// naming a key the enclave does not hold is useless to whoever replays it.
    pub fn public_key_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// Open a `CiphertextForRecipient` and return what KMS put inside it.
    pub fn unwrap_ciphertext(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let enveloped = parse_enveloped(ciphertext)?;

        let cek = self.unwrap_key(&enveloped)?;
        decrypt_content(&enveloped, &cek)
    }

    /// Recover the content-encryption key from the single recipient.
    fn unwrap_key(&self, enveloped: &EnvelopedData) -> Result<Vec<u8>> {
        let recipients = enveloped.recip_infos.0.as_slice();
        // Exactly one. More than one means somebody other than this enclave
        // can also open the content, which is the one thing this whole
        // mechanism exists to prevent — so it is refused rather than ignored.
        let [recipient] = recipients else {
            bail!(
                "expected exactly one CMS recipient, found {}",
                recipients.len()
            );
        };
        let RecipientInfo::Ktri(ktri) = recipient else {
            bail!("expected a key-transport recipient, found another RecipientInfo variant");
        };
        if ktri.key_enc_alg.oid != ID_RSAES_OAEP {
            bail!(
                "expected RSAES-OAEP key transport, found OID {}",
                ktri.key_enc_alg.oid
            );
        }

        let mut out = vec![0u8; self.oaep.min_output_size()];
        let plaintext = self
            .oaep
            .decrypt(
                &OAEP_SHA256_MGF1SHA256,
                ktri.enc_key.as_bytes(),
                &mut out,
                // KMS uses no OAEP label. Passing one would simply fail to
                // decrypt, so this is not a place a mistake stays quiet.
                None,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "unwrapping the content-encryption key. The response was encrypted to a \
                     different public key than this boot generated."
                )
            })?;
        Ok(plaintext.to_vec())
    }
}

/// `ContentInfo` → `EnvelopedData`, refusing anything else.
fn parse_enveloped(ciphertext: &[u8]) -> Result<EnvelopedData> {
    let der = ber_to_der(ciphertext).context("transcoding CiphertextForRecipient to DER")?;
    let info = ContentInfo::from_der(&der).context("parsing CiphertextForRecipient as CMS")?;
    if info.content_type != ID_ENVELOPED_DATA {
        bail!(
            "expected CMS enveloped-data, found content type {}",
            info.content_type
        );
    }
    // Round-tripped through DER rather than downcast: `content` is an `Any`,
    // and re-encoding is how the crate hands over the inner structure.
    let inner = info
        .content
        .to_der()
        .context("re-encoding the CMS content")?;
    EnvelopedData::from_der(&inner).context("parsing the CMS enveloped-data")
}

/// AES-256-CBC, with the IV from the algorithm parameters.
fn decrypt_content(enveloped: &EnvelopedData, cek: &[u8]) -> Result<Vec<u8>> {
    let content = &enveloped.encrypted_content;
    if content.content_type != ID_DATA {
        bail!(
            "expected id-data inside the envelope, found {}",
            content.content_type
        );
    }
    if content.content_enc_alg.oid != ID_AES_256_CBC {
        bail!(
            "expected AES-256-CBC content encryption, found OID {}",
            content.content_enc_alg.oid
        );
    }

    let iv = content
        .content_enc_alg
        .parameters
        .as_ref()
        .context("AES-CBC algorithm parameters are missing the IV")?
        .decode_as::<der::asn1::OctetString>()
        .context("AES-CBC IV is not an OCTET STRING")?;
    let iv: [u8; AES_CBC_IV_LEN] = iv
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("AES-CBC IV is not {AES_CBC_IV_LEN} bytes"))?;

    let mut buffer = content
        .encrypted_content
        .as_ref()
        .context("the envelope carries no encrypted content")?
        .as_bytes()
        .to_vec();

    let key = UnboundCipherKey::new(&AES_256, cek)
        .map_err(|_| anyhow::anyhow!("content-encryption key is not 32 bytes"))?;
    let decrypting = PaddedBlockDecryptingKey::cbc_pkcs7(key)
        .map_err(|_| anyhow::anyhow!("preparing AES-256-CBC"))?;
    let plaintext = decrypting
        .decrypt(&mut buffer, DecryptionContext::Iv128(iv.into()))
        .map_err(|_| anyhow::anyhow!("decrypting the enveloped content"))?;
    Ok(plaintext.to_vec())
}

/// Far above a real EnvelopedData's handful of levels; low enough that `30 80`
/// repeated by a hostile parent cannot exhaust the enclave's stack.
const MAX_DEPTH: usize = 64;

/// `CiphertextForRecipient`, from the BER KMS sends to the DER `cms` reads.
///
/// KMS encodes the CMS with indefinite-length constructed values and chunks
/// OCTET STRINGs into constructed form, which `der` refuses ("indefinite length
/// disallowed"). Found on the first boot on Nitro hardware: KMS released the
/// key and the enclave could not read the answer.
///
/// Every TLV is rewritten with a definite length, and chunked OCTET STRINGs
/// collapse into primitive ones; DER comes back unchanged. It runs before
/// anything is authenticated — the parent proxies these bytes — so it fails
/// closed on anything it does not expect and bounds its own recursion. Taken
/// from enclavia-protocol's `kms_recipient`, which met the same KMS.
fn ber_to_der(input: &[u8]) -> Result<Vec<u8>> {
    let (out, rest) = transcode(input, 0)?;
    if !rest.is_empty() {
        bail!("{} bytes after the end of the value", rest.len());
    }
    Ok(out)
}

/// One TLV: its definite-length DER, and the input after it.
fn transcode(input: &[u8], depth: usize) -> Result<(Vec<u8>, &[u8])> {
    if depth > MAX_DEPTH {
        bail!("nested deeper than {MAX_DEPTH} levels");
    }
    let id = *input.first().context("unexpected end of input")?;
    if id & 0x1f == 0x1f {
        bail!("high tag numbers are not supported");
    }
    let constructed = id & 0x20 != 0;
    let (len, after_len) = read_len(&input[1..])?;

    if !constructed {
        let len = len.context("an indefinite length on a primitive value")?;
        let content = after_len
            .get(..len)
            .context("a primitive value runs past the end")?;
        return Ok((emit(id, content), &after_len[len..]));
    }

    let mut children = Vec::new();
    let after = match len {
        Some(len) => {
            let mut region = after_len
                .get(..len)
                .context("a constructed value runs past the end")?;
            while !region.is_empty() {
                let (child, rest) = transcode(region, depth + 1)?;
                children.push(child);
                region = rest;
            }
            &after_len[len..]
        }
        // Children until end-of-contents, 00 00.
        None => {
            let mut region = after_len;
            loop {
                if let [0, 0, rest @ ..] = region {
                    break rest;
                }
                let (child, rest) = transcode(region, depth + 1)?;
                children.push(child);
                region = rest;
            }
        }
    };

    // A chunked OCTET STRING becomes one primitive: the universal constructed
    // form (0x24), and an IMPLICIT one under a context tag whose children are
    // all OCTET STRINGs — how KMS sends EncryptedContentInfo's
    // `encryptedContent [0]` (0xA0 → 0x80). Any other constructed value, an
    // EXPLICIT [0] wrapper included, keeps its children as they are.
    let universal_octets = id == 0x24;
    let context_octets = id & 0xc0 == 0x80
        && !children.is_empty()
        && children.iter().all(|c| c.first() == Some(&0x04));
    let mut body = Vec::new();
    if universal_octets || context_octets {
        for child in &children {
            body.extend_from_slice(octet_value(child)?);
        }
        let id = if universal_octets { 0x04 } else { id & !0x20 };
        return Ok((emit(id, &body), after));
    }
    for child in &children {
        body.extend_from_slice(child);
    }
    Ok((emit(id, &body), after))
}

/// An ASN.1 length, `None` for indefinite, and the input after it.
fn read_len(input: &[u8]) -> Result<(Option<usize>, &[u8])> {
    let (&first, rest) = input.split_first().context("a truncated length")?;
    match first {
        0x80 => Ok((None, rest)),
        short if short & 0x80 == 0 => Ok((Some(short as usize), rest)),
        long => {
            let n = (long & 0x7f) as usize;
            let bytes = rest
                .get(..n)
                .filter(|_| n <= 4)
                .context("a bad long-form length")?;
            let len = bytes.iter().fold(0usize, |len, &b| (len << 8) | b as usize);
            Ok((Some(len), &rest[n..]))
        }
    }
}

fn emit(id: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let significant = &be[be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1)..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// The value of a transcoded primitive OCTET STRING.
fn octet_value(der: &[u8]) -> Result<&[u8]> {
    if der.first() != Some(&0x04) {
        bail!("a chunk of an OCTET STRING is not an OCTET STRING");
    }
    let (len, content) = read_len(&der[1..])?;
    content
        .get(..len.context("an indefinite OCTET STRING chunk")?)
        .context("a truncated OCTET STRING chunk")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::cipher::{EncryptionContext, PaddedBlockEncryptingKey};
    use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};
    use cms::enveloped_data::{
        EncryptedContentInfo, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfos,
    };
    use der::asn1::{Any, OctetString, SetOfVec};
    use spki::AlgorithmIdentifierOwned;

    /// Build the message KMS would have built.
    ///
    /// A round-trip against a hand-rolled encoder is the only honest way to
    /// test this offline: the real bytes come from a service we cannot call
    /// from here, so the test has to construct the same structure and prove the
    /// unwrap recovers what went in.
    fn envelope(
        recipient: &RecipientKey,
        payload: &[u8],
        content_type: ObjectIdentifier,
        key_alg: ObjectIdentifier,
        content_alg: ObjectIdentifier,
        recipients: usize,
    ) -> Vec<u8> {
        let cek = [0x5au8; 32];
        let iv = [0x11u8; AES_CBC_IV_LEN];

        // Content, under the content-encryption key. `less_safe_encrypt` pads
        // and grows the buffer in place, so it ends up PKCS#7-padded exactly
        // as the unwrap expects to find it.
        let mut buffer = payload.to_vec();
        let key = UnboundCipherKey::new(&AES_256, &cek).unwrap();
        let encrypting = PaddedBlockEncryptingKey::cbc_pkcs7(key).unwrap();
        encrypting
            .less_safe_encrypt(&mut buffer, EncryptionContext::Iv128(iv.into()))
            .unwrap();

        // The content-encryption key, to our public key.
        let public = PublicEncryptingKey::from_der(recipient.public_key_der()).unwrap();
        let oaep = OaepPublicEncryptingKey::new(public).unwrap();
        let mut wrapped = vec![0u8; oaep.key_size_bytes()];
        let wrapped_len = oaep
            .encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut wrapped, None)
            .unwrap()
            .len();
        wrapped.truncate(wrapped_len);

        let ktri = KeyTransRecipientInfo {
            version: cms::content_info::CmsVersion::V0,
            rid: RecipientIdentifier::SubjectKeyIdentifier(
                x509_cert::ext::pkix::SubjectKeyIdentifier(
                    OctetString::new(vec![0u8; 20]).unwrap(),
                ),
            ),
            key_enc_alg: AlgorithmIdentifierOwned {
                oid: key_alg,
                parameters: None,
            },
            enc_key: OctetString::new(wrapped).unwrap(),
        };
        let mut infos = SetOfVec::new();
        for _ in 0..recipients {
            // `SetOfVec` rejects duplicates, so a second recipient differs in
            // its identifier — enough to make the count what the test needs.
            let mut other = ktri.clone();
            other.rid = RecipientIdentifier::SubjectKeyIdentifier(
                x509_cert::ext::pkix::SubjectKeyIdentifier(
                    OctetString::new(vec![infos.len() as u8; 20]).unwrap(),
                ),
            );
            infos.insert(RecipientInfo::Ktri(other)).unwrap();
        }

        let enveloped = EnvelopedData {
            version: cms::content_info::CmsVersion::V0,
            originator_info: None,
            recip_infos: RecipientInfos(infos),
            encrypted_content: EncryptedContentInfo {
                content_type,
                content_enc_alg: AlgorithmIdentifierOwned {
                    oid: content_alg,
                    parameters: Some(
                        Any::from_der(&OctetString::new(iv.to_vec()).unwrap().to_der().unwrap())
                            .unwrap(),
                    ),
                },
                encrypted_content: Some(OctetString::new(buffer).unwrap()),
            },
            unprotected_attrs: None,
        };

        ContentInfo {
            content_type: ID_ENVELOPED_DATA,
            content: Any::from_der(&enveloped.to_der().unwrap()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn well_formed(recipient: &RecipientKey, payload: &[u8]) -> Vec<u8> {
        envelope(
            recipient,
            payload,
            ID_DATA,
            ID_RSAES_OAEP,
            ID_AES_256_CBC,
            1,
        )
    }

    #[test]
    fn a_public_key_is_an_spki_of_a_workable_size() {
        let key = RecipientKey::generate().unwrap();
        // The NSM caps `public_key`; an RSA-2048 SPKI is nowhere near it, and
        // this is the assertion that would catch a key size change that is.
        assert!(
            (256..1024).contains(&key.public_key_der().len()),
            "unexpected SPKI length {}",
            key.public_key_der().len()
        );
        PublicEncryptingKey::from_der(key.public_key_der()).expect("a parseable SPKI");
    }

    /// The load-bearing one: what KMS would send comes back out intact.
    #[test]
    fn a_well_formed_envelope_round_trips() {
        let key = RecipientKey::generate().unwrap();
        let secret = [0x42u8; 32];
        let opened = key.unwrap_ciphertext(&well_formed(&key, &secret)).unwrap();
        assert_eq!(opened, secret);
    }

    /// What KMS actually sends: every constructed value indefinite-length,
    /// every OCTET STRING — the wrapped key, the IV, the encrypted content —
    /// chunked. The first boot on Nitro failed on exactly this.
    #[test]
    fn an_envelope_in_kms_ber_round_trips() {
        let key = RecipientKey::generate().unwrap();
        let secret = [0x42u8; 32];
        let der = well_formed(&key, &secret);
        let ber = as_kms_sends(&der);
        assert_ne!(ber, der);
        assert_eq!(key.unwrap_ciphertext(&ber).unwrap(), secret);
    }

    /// Re-encode one DER value the way KMS does.
    fn as_kms_sends(der: &[u8]) -> Vec<u8> {
        fn tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
            let (len, at) = match input[1] {
                short if short < 0x80 => (short as usize, 2),
                long => {
                    let n = (long & 0x7f) as usize;
                    let len = input[2..2 + n]
                        .iter()
                        .fold(0, |l, &b| (l << 8) | b as usize);
                    (len, 2 + n)
                }
            };
            (input[0], &input[at..at + len], &input[at + len..])
        }
        fn chunked(id: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![id | 0x20, 0x80];
            for chunk in content.chunks(5) {
                out.extend_from_slice(&[0x04, chunk.len() as u8]);
                out.extend_from_slice(chunk);
            }
            out.extend_from_slice(&[0, 0]);
            out
        }
        let (id, content, _) = tlv(der);
        match id {
            0x04 | 0x80 if content.len() > 5 => chunked(id, content),
            constructed if constructed & 0x20 != 0 => {
                let mut out = vec![id, 0x80];
                let mut rest = content;
                while !rest.is_empty() {
                    let (_, _, after) = tlv(rest);
                    out.extend(as_kms_sends(&rest[..rest.len() - after.len()]));
                    rest = after;
                }
                out.extend_from_slice(&[0, 0]);
                out
            }
            _ => der.to_vec(),
        }
    }

    /// A payload that is not a whole number of blocks, to prove the PKCS#7
    /// padding is actually being stripped rather than accidentally absent.
    #[test]
    fn an_unaligned_payload_round_trips() {
        let key = RecipientKey::generate().unwrap();
        let payload = b"thirty-one bytes of content xxx";
        assert_eq!(payload.len() % 16, 15);
        let opened = key.unwrap_ciphertext(&well_formed(&key, payload)).unwrap();
        assert_eq!(opened, payload);
    }

    /// Two recipients means somebody besides this enclave can open the content.
    /// That is the exact thing `Recipient` exists to prevent, so it is refused
    /// rather than quietly using the first one.
    #[test]
    fn more_than_one_recipient_is_refused() {
        let key = RecipientKey::generate().unwrap();
        let bytes = envelope(&key, b"secret", ID_DATA, ID_RSAES_OAEP, ID_AES_256_CBC, 2);
        let err = key.unwrap_ciphertext(&bytes).unwrap_err().to_string();
        assert!(err.contains("exactly one"), "unexpected error: {err}");
    }

    #[test]
    fn an_unexpected_key_transport_algorithm_is_refused() {
        let key = RecipientKey::generate().unwrap();
        // rsaEncryption — PKCS#1 v1.5, not OAEP.
        let pkcs1 = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let bytes = envelope(&key, b"secret", ID_DATA, pkcs1, ID_AES_256_CBC, 1);
        let err = key.unwrap_ciphertext(&bytes).unwrap_err().to_string();
        assert!(err.contains("RSAES-OAEP"), "unexpected error: {err}");
    }

    #[test]
    fn an_unexpected_content_encryption_algorithm_is_refused() {
        let key = RecipientKey::generate().unwrap();
        // aes128-CBC: the right shape, the wrong strength.
        let aes128 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.2");
        let bytes = envelope(&key, b"secret", ID_DATA, ID_RSAES_OAEP, aes128, 1);
        let err = key.unwrap_ciphertext(&bytes).unwrap_err().to_string();
        assert!(err.contains("AES-256-CBC"), "unexpected error: {err}");
    }

    #[test]
    fn an_unexpected_inner_content_type_is_refused() {
        let key = RecipientKey::generate().unwrap();
        let bytes = envelope(
            &key,
            b"secret",
            ID_ENVELOPED_DATA,
            ID_RSAES_OAEP,
            ID_AES_256_CBC,
            1,
        );
        let err = key.unwrap_ciphertext(&bytes).unwrap_err().to_string();
        assert!(err.contains("id-data"), "unexpected error: {err}");
    }

    /// An envelope addressed to a different enclave's key. This is the replay
    /// case: a document naming a public key we do not hold is useless.
    #[test]
    fn an_envelope_for_another_key_is_refused() {
        let ours = RecipientKey::generate().unwrap();
        let theirs = RecipientKey::generate().unwrap();
        let err = ours
            .unwrap_ciphertext(&well_formed(&theirs, b"secret"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("different public key"), "unexpected: {err}");
    }

    #[test]
    fn garbage_is_refused_rather_than_panicking() {
        let key = RecipientKey::generate().unwrap();
        assert!(key.unwrap_ciphertext(b"").is_err());
        assert!(key.unwrap_ciphertext(&[0xffu8; 64]).is_err());
    }

    #[test]
    fn indefinite_lengths_and_chunked_strings_become_der() {
        // DER passes through unchanged: SEQUENCE { INTEGER 1 }.
        let der = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(ber_to_der(&der).unwrap(), der);
        assert_eq!(
            ber_to_der(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]).unwrap(),
            der
        );

        // A chunked OCTET STRING, indefinite and definite: "ab" + "cd".
        let octets = [0x04, 0x04, 0x61, 0x62, 0x63, 0x64];
        let chunks = [0x04, 0x02, 0x61, 0x62, 0x04, 0x02, 0x63, 0x64];
        assert_eq!(
            ber_to_der(&[&[0x24, 0x80][..], &chunks, &[0, 0]].concat()).unwrap(),
            octets
        );
        assert_eq!(
            ber_to_der(&[&[0x24, 0x08][..], &chunks].concat()).unwrap(),
            octets
        );

        // encryptedContent [0] IMPLICIT, chunked as KMS sends it.
        let context = [0x80, 0x04, 0x61, 0x62, 0x63, 0x64];
        assert_eq!(
            ber_to_der(&[&[0xA0, 0x80][..], &chunks, &[0, 0]].concat()).unwrap(),
            context
        );

        // An EXPLICIT [0] wrapper stays constructed: ContentInfo.content.
        assert_eq!(
            ber_to_der(&[0xA0, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0, 0, 0, 0]).unwrap(),
            [0xA0, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]
        );
    }

    /// The parent supplies these bytes, before anything is authenticated.
    #[test]
    fn hostile_input_is_refused_rather_than_followed() {
        let deep = [[0x30, 0x80].repeat(5000), [0, 0].repeat(5000)].concat();
        assert!(
            ber_to_der(&deep).is_err(),
            "unbounded nesting must be refused"
        );
        assert!(ber_to_der(&[0x30, 0x80, 0x02, 0x01]).is_err(), "truncated");
        assert!(
            ber_to_der(&[0x04, 0x80, 0x00, 0x00]).is_err(),
            "indefinite primitive"
        );
        assert!(
            ber_to_der(&[0x30, 0x03, 0x02, 0x01, 0x01, 0xff]).is_err(),
            "trailing bytes"
        );
        assert!(
            ber_to_der(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_err(),
            "five-byte length"
        );
        assert!(ber_to_der(&[]).is_err());
    }
}
