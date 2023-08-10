use crate::rosetta::{EnvelopePair, Request, RequestEnvelope, RequestType, SignedTransaction};
use crate::send_request_proto;
use candid::{CandidType, Principal};
use ic_agent::Identity;
use ic_agent::{
    agent::{EnvelopeContent, UpdateBuilder},
    identity::Secp256k1Identity,
    Agent,
};
use ic_ledger_types::{
    AccountIdentifier, ChecksumError, Memo, Subaccount, Timestamp, Tokens, DEFAULT_SUBACCOUNT,
};
use pkcs8::EncodePublicKey;
use tw_encoding::hex;

use k256::{ecdsa, ecdsa::signature::Signer, SecretKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    str::FromStr,
    time::SystemTime,
};

pub const DOMAIN_IC_REQUEST: &[u8; 11] = b"\x0Aic-request";
pub const IC_URL: &str = "https://ic0.app";
pub const LEDGER_CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const METHOD_NAME: &str = "send_pb";

/// An error for reporting invalid Account Identifiers.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountIdParseError {
    InvalidChecksum(ChecksumError),
    InvalidLength(Vec<u8>),
}

/// Type alias for a sha256 result (ie. a u256).
type Sha256Hash = [u8; 32];

/// A Request ID.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Deserialize, Serialize)]
pub struct RequestId(Sha256Hash);

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub memo: Memo,
    pub amount: Tokens,
    pub fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdentifier,
    pub created_at_time: Option<Timestamp>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct RequestStatus {
    pub canister_id: String,
    pub request_id: String,
    pub content: String,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct Ingress {
    pub call_type: String,
    pub request_id: Option<String>,
    pub content: String,
    pub role: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct IngressWithRequestId {
    pub ingress: Ingress,
    pub request_status: RequestStatus,
}

pub fn sign_transfer(
    memo: u64,
    amount: u64,
    fee: u64,
    from_subaccount: Subaccount,
    from_principal: Principal,
    to_principal: Principal,
    to_subaccount: Subaccount,
    secret_key: Vec<u8>,
    ingress_expiry_duration: Duration,
) -> Result<String, String> {
    let to_account_identifier_crc = AccountIdentifier::new(&to_principal, &DEFAULT_SUBACCOUNT);
    let to = AccountIdentifier::from_hex(to_account_identifier_crc.to_hex().as_ref())
        .map_err(|e| e.to_string())?;
    let now = SystemTime::now();
    let send_args = SendArgs {
        memo: Memo(memo),
        amount: Tokens::from_e8s(amount),
        fee: Tokens::from_e8s(fee),
        from_subaccount: None,
        to,
        created_at_time: Some(Timestamp {
            timestamp_nanos: now
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| "error generating timestamp".to_string())?
                .as_nanos() as u64,
        }),
    };

    sign(
        LEDGER_CANISTER.to_string(),
        METHOD_NAME.to_string(),
        send_args,
        secret_key.as_slice(),
        from_principal,
        from_subaccount,
        IC_URL.to_string(),
        ingress_expiry_duration,
    )
}

pub fn sign(
    canister_id: String,
    method_name: String,
    send_args: SendArgs,
    secret_key: &[u8],
    sender: Principal,
    sender_subaccount: Subaccount,
    ic_url: String,
    ingress_expiry: Duration,
) -> Result<String, String> {
    let canister_id = Principal::from_text(canister_id).map_err(|e| e.to_string())?;

    // Encode transfer arguments with protobuf to convert it to array (vector) for u8s
    let arg = send_request_proto::into_bytes(send_args.clone())?;

    sign_implementation(
        canister_id,
        method_name,
        arg,
        secret_key,
        sender,
        ic_url,
        ingress_expiry,
        send_args
            .created_at_time
            .ok_or("creation timestamp not found")?
            .timestamp_nanos,
    )
}

fn sign_implementation(
    canister_id: Principal,
    method_name: String,
    arg: Vec<u8>,
    secret_key: &[u8],
    sender: Principal,
    ic_url: String,
    ingress_expiry: Duration,
    creation_time_nanos: u64,
) -> Result<String, String> {
    // Calculate ingress expiry timestamp
    let ingress_expiry_timestamp = Duration::from_nanos(creation_time_nanos)
        .checked_add(ingress_expiry)
        .ok_or("Error creating valid ingress expiry timestamp")?
        .as_nanos() as u64;
    // Build update call envelope
    let call_envelope = EnvelopeContent::Call {
        canister_id,
        method_name: method_name.clone(),
        arg: arg.clone(),
        nonce: None,
        sender,
        ingress_expiry: ingress_expiry_timestamp,
    };
    let request_id = call_envelope.to_request_id();

    // Build read state envelope
    let read_state_envelope = EnvelopeContent::ReadState {
        ingress_expiry: ingress_expiry_timestamp,
        sender,
        paths: vec![vec!["request_status".into(), request_id.as_slice().into()]],
    };

    // Build secret key
    let secret_key =
        SecretKey::from_slice(secret_key).map_err(|_| "Error extracting secret key".to_string())?;
    let identity = Box::new(Secp256k1Identity::from_private_key(secret_key.clone()));
    let public_key_bytes = secret_key
        .public_key()
        .to_public_key_der()
        .map_err(|e| e.to_string())?
        .to_vec();

    // Get the signature from the ic agent
    let call_sig = identity.sign(&call_envelope).unwrap();
    let request_status_sig = identity.sign(&read_state_envelope).unwrap();

    let envelop_pair = EnvelopePair {
        update: RequestEnvelope {
            content: call_envelope,
            sender_pubkey: Some(public_key_bytes.clone()),
            sender_sig: call_sig.signature,
        },
        read_state: RequestEnvelope {
            content: read_state_envelope,
            sender_pubkey: Some(public_key_bytes),
            sender_sig: request_status_sig.signature,
        },
    };
    let request: Request = (RequestType::Send, vec![envelop_pair]);
    let signed_transaction: SignedTransaction = vec![request];
    Ok(hex::encode(
        &serde_cbor::to_vec(&signed_transaction).map_err(|_| "error during cbor serialization")?,
        false,
    ))
}

fn sign_secp256k1(content: &[u8], secret_key_slice: &[u8]) -> Result<Vec<u8>, String> {
    let secret_key = SecretKey::from_slice(secret_key_slice)
        .map_err(|_| "Error extracting secret key".to_string())?;
    let signing_key: ecdsa::SigningKey = secret_key.into();
    let (ecdsa_sig, _recovery_id) = signing_key.sign(content);
    let r = ecdsa_sig.r().as_ref().to_bytes();
    let s = ecdsa_sig.s().as_ref().to_bytes();
    let mut bytes = [0u8; 64];
    if r.len() > 32 || s.len() > 32 {
        return Err("Cannot create secp256k1 signature: malformed signature.".to_string());
    }
    bytes[(32 - r.len())..32].clone_from_slice(&r);
    bytes[32 + (32 - s.len())..].clone_from_slice(&s);
    Ok(bytes.to_vec()) //Signature bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        sign::interface_spec::envelope::EnvelopeContent as InternalEnvelopeContent,
        sign::interface_spec::request_id,
        sign_transfer_sendpb::{sign_secp256k1, sign_transfer, AccountIdentifier},
    };

    use ic_agent::{agent::EnvelopeContent, identity::Secp256k1Identity, Identity};

    use candid::Principal;
    use ic_ledger_types::Subaccount;
    use k256::{
        ecdsa, pkcs8,
        pkcs8::{Document, EncodePublicKey},
        PublicKey, SecretKey,
    };
    use std::time::Duration;

    pub const IC_URL: &str = "https://ic0.app";
    pub const LEDGER_CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
    pub const METHOD_NAME: &str = "send_pb";
    pub const ECDSA_SECP256K1: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICJxApEbuZznKFpV+VKACRK30i6+7u5Z13/DOl18cIC+oAcGBSuBBAAK
oUQDQgAEPas6Iag4TUx+Uop+3NhE6s3FlayFtbwdhRVjvOar0kPTfE/N8N6btRnd
74ly5xXEBNSXiENyxhEuzOZrIWMCNQ==
-----END EC PRIVATE KEY-----";
    pub const PRINCIPAL_ID_TEXT: &str =
        "meky5-ylcvy-7z53d-oqtoh-yxmvs-akp7v-p2ugh-swlsw-tpdw5-jl6wg-nqe";

    pub fn get_secp256k1_secret_key() -> Result<SecretKey, String> {
        SecretKey::from_sec1_pem(ECDSA_SECP256K1)
            .map_err(|_| pkcs8::Error::KeyMalformed.to_string())
    }

    pub fn get_secp256k1_secret_key_bytes() -> Result<Vec<u8>, String> {
        Ok(get_secp256k1_secret_key()?.to_bytes().to_vec())
    }

    pub fn get_secp256k1_public_key() -> Result<PublicKey, String> {
        let public_key = Ok(get_secp256k1_secret_key()?.public_key());
        public_key
    }

    pub fn get_secp256k1_der_public_key(public_key: PublicKey) -> Document {
        let der_encoded_public_key = public_key
            .to_public_key_der()
            .expect("Cannot DER encode secp256k1 public key.");
        der_encoded_public_key
    }

    pub fn get_secp256k1_der_hex_public_key(public_key_der: Document) -> String {
        hex::encode(public_key_der.as_bytes(), false)
    }

    pub fn get_secp256k1_signing_key_bytes(secret_key: SecretKey) -> Vec<u8> {
        let signing_key: ecdsa::SigningKey = secret_key.into();
        signing_key.to_bytes().to_vec()
    }

    pub fn get_principal_from_text(principal_text: &str) -> Result<Principal, String> {
        Principal::from_text(principal_text).map_err(|e| e.to_string())
    }

    #[test]
    fn test_secp256k_key_bytes() -> Result<(), String> {
        let data: [u8; 16] = [1; 16];
        let identity = Secp256k1Identity::from_pem(ECDSA_SECP256K1.as_bytes())
            .map_err(|_| "Error reading pem bytes")?;
        let canister_id = "bkyz2-fmaaa-aaaaa-qaaaq-cai".parse().unwrap();
        let method_name = "greet".to_string();
        let sender = identity.sender().unwrap();
        let message = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 0,
            sender,
            canister_id,
            method_name: method_name.clone(),
            arg: vec![1, 1, 1, 1, 1, 1, 1, 1],
        };
        let internal_message = InternalEnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 0,
            sender,
            canister_id,
            method_name: method_name.clone(),
            arg: vec![1, 1, 1, 1, 1, 1, 1, 1],
        };

        let result1 = identity
            .sign(&message)?
            .signature
            .ok_or("Invalid signature in result1")?;

        let request_id = internal_message.to_request_id();

        let request_id_signable = request_id::make_sig_data(&request_id);
        assert_eq!(
            &request_id_signable[..],
            &message.to_request_id().signable()[..]
        );

        let secret_key = get_secp256k1_secret_key_bytes()?;

        let result2 = sign_secp256k1(request_id_signable.as_slice(), secret_key.as_slice())?;
        assert_eq!(&result1[..], &result2[..]);

        let paths: Vec<Vec<Vec<u8>>> = vec![vec![
            "request_status".as_bytes().to_vec(),
            request_id.0.as_slice().to_vec(),
        ]];
        let read_state = EnvelopeContent::ReadState {
            ingress_expiry: 0,
            sender,
            paths: vec![vec![
                "request_status".into(),
                request_id.0.as_slice().into(),
            ]],
        };

        let read_state_signable =
            request_id::make_sig_data(&request_id::representation_independent_hash_read_state(
                0,
                paths.as_slice(),
                sender.as_slice().to_vec(),
                None,
            ));

        assert_eq!(
            &read_state_signable[..],
            &read_state.to_request_id().signable()[..]
        );

        Ok(())
    }

    #[test]
    pub fn test_call_sign() -> Result<(), String> {
        let ingress_expiry_duration = Duration::from_secs(1 * 60);
        let canister_id = Principal::from_text(LEDGER_CANISTER).map_err(|e| e.to_string())?;
        let from_subaccount = Subaccount([0; 32]);
        let from_principal = get_principal_from_text(
            "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe",
        )?;
        let from = AccountIdentifier::new(&from_principal, &DEFAULT_SUBACCOUNT);
        let secret_key = get_secp256k1_secret_key_bytes()?;
        let to_principal = get_principal_from_text(
            "t4u4z-y3dur-j63pk-nw4rv-yxdbt-agtt6-nygn7-ywh6y-zm2f4-sdzle-3qe",
        )?;
        let to_subaccount = Subaccount([0; 32]);

        let transfer: String = sign_transfer(
            0,
            100000000,
            10000,
            from_subaccount,
            from_principal,
            to_principal,
            to_subaccount,
            secret_key,
            ingress_expiry_duration,
        )?;
        println!("{:?}", transfer);
        Ok(())
    }
}
