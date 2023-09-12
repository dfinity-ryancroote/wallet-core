use candid::{types::principal::PrincipalError, Principal as CandidPrincipal};
use serde::{Deserialize, Serialize};

use tw_keypair::ecdsa::secp256k1::PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal(CandidPrincipal);

impl Principal {
    pub const fn from_slice(slice: &[u8]) -> Self {
        let principal = CandidPrincipal::from_slice(slice);
        Self(principal)
    }

    pub const fn anonymous() -> Self {
        Self(CandidPrincipal::anonymous())
    }

    pub fn self_authenticating<P: AsRef<[u8]>>(public_key: P) -> Self {
        Self(CandidPrincipal::self_authenticating(public_key))
    }

    pub fn from_text<S: AsRef<str>>(text: S) -> Result<Self, PrincipalError> {
        CandidPrincipal::from_text(text).map(|p| Self(p))
    }

    pub fn to_text(&self) -> String {
        self.0.to_text()
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<&PublicKey> for Principal {
    /// Takes a Secp256k1 public key, DER-encodes the public key,
    /// and creates a principal from the encoding.
    fn from(public_key: &PublicKey) -> Self {
        let principal = CandidPrincipal::self_authenticating(public_key.der_encoded());
        Self(principal)
    }
}
