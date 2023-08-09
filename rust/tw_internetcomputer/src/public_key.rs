use k256;
use pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};
use tw_encoding::hex;

/// CurveType is the type of cryptographic curve associated with a PublicKey.  * secp256k1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * secp256r1: SEC compressed - `33 bytes` (https://secg.org/sec1-v2.pdf#subsubsection.2.3.3) * edwards25519: `y (255-bits) || x-sign-bit (1-bit)` - `32 bytes` (https://ed25519.cr.yp.to/ed25519-20110926.pdf) * tweedle: 1st pk : Fq.t (32 bytes) || 2nd pk : Fq.t (32 bytes) (https://github.com/CodaProtocol/coda/blob/develop/rfcs/0038-rosetta-construction-api.md#marshal-keys)
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them
/// as `#[repr(C)]` which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGenericEnum))]
pub enum CurveType {
    #[serde(rename = "secp256k1")]
    Secp256K1,
    #[serde(rename = "secp256r1")]
    Secp256R1,
    #[serde(rename = "edwards25519")]
    Edwards25519,
    #[serde(rename = "tweedle")]
    Tweedle,
}

/// PublicKey contains a public key byte array for a particular CurveType
/// encoded in hex.  Note that there is no PrivateKey struct as this is NEVER
/// the concern of an implementation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct PublicKey {
    /// Hex-encoded public key bytes in the format specified by the CurveType.
    #[serde(rename = "hex_bytes")]
    pub hex_bytes: String,

    #[serde(rename = "curve_type")]
    pub curve_type: CurveType,
}

impl PublicKey {
    pub fn new(hex_bytes: String, curve_type: CurveType) -> PublicKey {
        PublicKey {
            hex_bytes,
            curve_type,
        }
    }
}

pub fn get_secp256k1_der_public_key(public_key: k256::PublicKey) -> Result<Vec<u8>, String> {
    let der_encoded_public_key = public_key
        .to_public_key_der()
        .map_err(|_| "Error der encoded public key".to_string())?;
    Ok(der_encoded_public_key.to_vec())
}

pub fn get_secp256k1_der_hex_public_key(public_key: k256::PublicKey) -> Result<PublicKey, String> {
    let public_key_der = get_secp256k1_der_public_key(public_key)?;
    Ok(PublicKey {
        hex_bytes: hex::encode(&public_key_der, false),
        curve_type: CurveType::Secp256K1,
    })
}
