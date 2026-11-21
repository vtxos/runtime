//! The TLS certificate the enclave serves, and where its key comes from.
//!
//! The key is generated **inside** the enclave and never leaves it. That is
//! the property the whole design rests on: a certificate whose private key
//! only ever existed in attested memory, whose hash the NSM then signs into an
//! attestation document. A client that checks the binding knows its TLS
//! session terminates in that enclave — not in the EC2 instance hosting it,
//! and not in a proxy the operator controls.
//!
//! Terminating TLS on the parent instance and forwarding plaintext would be
//! far simpler and would give away the entire point.
//!
//! ## Why self-signed
//!
//! No CA would add anything. A client trusts this certificate because an
//! attestation document — signed by the NSM, naming this runtime and guest —
//! binds its hash, and that is checked on every exchange a client identifies
//! the enclave by. A CA's signature says only that someone controlled a domain,
//! which the operator does as surely as the enclave; and no client here has a
//! domain to check — it signs in with its share of the wallet key, which
//! belongs to no domain. So the enclave makes its certificate itself, at every
//! boot:
//! nothing to issue, renew, store or rate-limit, and a key that exists only in
//! this boot's memory.
//!
//! ## Where the key's randomness comes from
//!
//! `rcgen` generates through `aws-lc-rs`, which draws from the kernel. That
//! deserves a note, because [`crate::random`] goes to some trouble to keep the
//! *guest's* `wasi:random` off the kernel pool and on the NSM directly.
//!
//! The two cases differ. The guest's concern is that the runtime might not be
//! in an enclave at all, and nothing in the kernel pool would say so — a
//! silent downgrade. Here, the enclave kernel has exactly one entropy source,
//! the NSM, which it uses to seed its pool before userspace starts; the boot
//! log shows `NSM RNG: returning rand bytes` immediately followed by
//! `random: crng init done`. So inside an enclave the kernel pool *is* NSM
//! entropy.
//!
//! What makes that argument safe to rely on is that it is checked rather than
//! assumed: an enclave image sets `ENCLAVE_RANDOM_SOURCE=nsm`, which refuses to
//! start without a working `/dev/nsm`. If the runtime got that far, it is in
//! an enclave.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A serving certificate and the rustls configuration built from it.
pub struct TlsIdentity {
    /// DER of the leaf certificate — the bytes a client hashes to check the
    /// attestation binding, and therefore what goes into `user_data`.
    pub certificate_der: Vec<u8>,
    pub config: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity")
            .field(
                "certificate_sha256",
                &hex::encode(nitro_attestation::sha256(&self.certificate_der)),
            )
            .finish()
    }
}

impl TlsIdentity {
    /// Build from a certificate chain, leaf first, and its key: the one constructor, which
    /// [`TlsIdentity::self_signed`] goes through.
    pub fn from_chain(chain: Vec<Vec<u8>>, key: PrivateKeyDer<'static>) -> Result<Self> {
        let leaf = chain.first().context("certificate chain is empty")?.clone();

        let certs: Vec<CertificateDer<'static>> =
            chain.into_iter().map(CertificateDer::from).collect();
        // The provider is named rather than left to `ServerConfig::builder()`,
        // which resolves it from rustls's compiled-in features and **panics**
        // when more than one is present. That is not hypothetical here: the
        // AWS SDK brings rustls with `ring` while this crate asks for
        // `aws-lc-rs`, so in any build with the `aws` feature both exist and
        // there is no unambiguous default. Naming it also keeps the whole
        // image on one implementation of these primitives.
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .context("selecting TLS protocol versions")?
        // No client certificates. Authentication is an approval signed with the
        // tenant's wallet share and bound to one request — see `crate::auth` —
        // and a certificate would be a second, weaker way to become a tenant
        // that could not bind an approval to a transaction.
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building the TLS configuration")?;

        // No session resumption. This is what makes "the certificate this
        // connection is using" a well-defined thing to attest.
        //
        // rustls sends a Certificate message **only on a full handshake**
        // (`server/tls13.rs`, gated on `full_handshake`). A resumed session is
        // authenticated by whatever the client cached from its original
        // handshake, so it presents no certificate at all: a client pinning
        // the certificate an attestation named would be checking its own
        // memory, and a signature binding "the certificate this connection
        // was served" would bind one this connection never showed.
        //
        // rustls exposes no way to ask which certificate an earlier session
        // used, so the only correct answer is to have no earlier session. The
        // cost is one handshake signature per connection.
        let mut config = config;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;

        // Preference order, and both are offered because both are served. A
        // gRPC client offers only `h2` and must be given it; curl and a browser
        // offer `http/1.1`, or no ALPN at all, and rustls skips the extension
        // entirely for the latter. The one client this turns away is one that
        // offers ALPN with no overlap, which is correct: there is no protocol
        // in common to speak.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(TlsIdentity {
            certificate_der: leaf,
            config: Arc::new(config),
        })
    }

    /// Generate a self-signed certificate for `domains` (`localhost` if none),
    /// with a key that exists only in this process's memory: what the enclave
    /// serves, made fresh at every boot. See the module docs for why no CA.
    pub fn self_signed(domains: &[String]) -> Result<Self> {
        let names: Vec<String> = if domains.is_empty() {
            vec!["localhost".to_string()]
        } else {
            domains.to_vec()
        };

        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
            .context("generating the TLS key")?;
        let certificate = rcgen::CertificateParams::new(names.clone())
            .context("building certificate parameters")?
            .self_signed(&key)
            .context("self-signing the certificate")?;

        let key_der = PrivateKeyDer::try_from(key.serialize_der())
            .map_err(|e| anyhow::anyhow!("encoding the TLS key: {e}"))?;
        let identity = Self::from_chain(vec![certificate.der().to_vec()], key_der)?;

        tracing::info!(
            domains = ?names,
            certificate_sha256 = %hex::encode(nitro_attestation::sha256(&identity.certificate_der)),
            "generated a self-signed TLS certificate inside the enclave"
        );
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_signed_identity_has_a_usable_certificate() {
        let identity = TlsIdentity::self_signed(&["enclave.test".to_string()]).unwrap();
        assert!(!identity.certificate_der.is_empty());

        // It must parse as X.509, or the hash going into the attestation
        // document would bind bytes no client could reproduce.
        use x509_parser::prelude::FromDer;
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&identity.certificate_der).unwrap();
        assert!(cert
            .subject_alternative_name()
            .unwrap()
            .is_some_and(|san| format!("{:?}", san.value).contains("enclave.test")));
    }

    /// Two enclaves, two keys. A shared certificate would let one enclave's
    /// attestation vouch for another's connections.
    #[test]
    fn each_identity_gets_its_own_key() {
        let a = TlsIdentity::self_signed(&[]).unwrap();
        let b = TlsIdentity::self_signed(&[]).unwrap();
        assert_ne!(a.certificate_der, b.certificate_der);
    }

    /// Both protocols, in preference order, on every serving identity.
    ///
    /// `from_chain` is the single constructor — `self_signed` routes through it —
    /// so this is the one place the list is stated.
    #[test]
    fn a_serving_identity_offers_h2_and_http11_in_that_order() {
        let identity = TlsIdentity::self_signed(&["enclave.test".to_string()])
            .expect("a self-signed identity");
        assert_eq!(
            identity.config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "gRPC needs h2 offered, and everything else needs http/1.1 kept"
        );
    }

    #[test]
    fn an_empty_chain_is_refused() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        assert!(TlsIdentity::from_chain(vec![], key_der).is_err());
    }
}
