use std::{
    time::SystemTime,
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    str::FromStr,
};
use std::ops::Sub;
use candid::{
    Principal,
    CandidType
};
use ic_ledger_types::{
    Memo,
    Subaccount,
    Tokens,
    Timestamp,
    AccountIdentifier as AccountIdentifierWithCRC
};
use ic_agent::agent::EnvelopeContent;
use ic_agent::{
    Agent,
    agent::{
        UpdateBuilder,
    },
    identity::{
        Secp256k1Identity,
    },
};
use std::time::Duration;
use k256::{
    ecdsa,
    ecdsa::{
        signature::Signer,
    },
    SecretKey
};
use serde::{Deserialize, Serialize};
use crate::send_request_proto;

pub const DOMAIN_IC_REQUEST: &[u8; 11] = b"\x0Aic-request";
pub const IC_URL: &str = "https://ic0.app";
pub const LEDGER_CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const METHOD_NAME: &str = "send_pb";


#[derive(Serialize, Deserialize, CandidType, Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountIdentifier {
    pub hash: [u8; 28],
}

impl AccountIdentifier {
    pub fn from_hex(hex_str: &str) -> Result<AccountIdentifier, String> {
        let hex: Vec<u8> = hex::decode(hex_str).map_err(|e| e.to_string())?;
        Self::from_slice(&hex[..]).map_err(|err| match err {
            // Since the input was provided in hex, return an error that is hex-friendly.
            AccountIdParseError::InvalidLength(_) => format!(
                "{} has a length of {} but we expected a length of 64 or 56",
                hex_str,
                hex_str.len()
            ),
            AccountIdParseError::InvalidChecksum(err) => err.to_string(),
        })
    }

    /// Converts a blob into an `AccountIdentifier`.
    ///
    /// The blob can be either:
    ///
    /// 1. The 32-byte canonical format (4 byte checksum + 28 byte hash).
    /// 2. The 28-byte hash.
    ///
    /// If the 32-byte canonical format is provided, the checksum is verified.
    pub fn from_slice(v: &[u8]) -> Result<AccountIdentifier, AccountIdParseError> {
        // Try parsing it as a 32-byte blob.
        match v.try_into() {
            Ok(h) => {
                // It's a 32-byte blob. Validate the checksum.
                check_sum(h).map_err(AccountIdParseError::InvalidChecksum)
            }
            Err(_) => {
                // Try parsing it as a 28-byte hash.
                match v.try_into() {
                    Ok(hash) => Ok(AccountIdentifier { hash }),
                    Err(_) => Err(AccountIdParseError::InvalidLength(v.to_vec())),
                }
            }
        }
    }

    pub fn generate_checksum(&self) -> [u8; 4] {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.hash);
        hasher.finalize().to_be_bytes()
    }
}

fn check_sum(hex: [u8; 32]) -> Result<AccountIdentifier, ChecksumError> {
    // Get the checksum provided
    let found_checksum = &hex[0..4];

    // Copy the hash into a new array
    let mut hash = [0; 28];
    hash.copy_from_slice(&hex[4..32]);

    let account_id = AccountIdentifier { hash };
    let expected_checksum = account_id.generate_checksum();

    // Check the generated checksum matches
    if expected_checksum == found_checksum {
        Ok(account_id)
    } else {
        Err(ChecksumError {
            input: hex,
            expected_checksum,
            found_checksum: found_checksum.try_into().unwrap(),
        })
    }
}

/// An error for reporting invalid checksums.
#[derive(Debug, PartialEq, Eq)]
pub struct ChecksumError {
    input: [u8; 32],
    expected_checksum: [u8; 4],
    found_checksum: [u8; 4],
}

impl Display for ChecksumError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Checksum failed for {}, expected check bytes {} but found {}",
            hex::encode(&self.input[..]),
            hex::encode(self.expected_checksum),
            hex::encode(self.found_checksum),
        )
    }
}

/// An error for reporting invalid Account Identifiers.
#[derive(Debug, PartialEq, Eq)]
pub enum AccountIdParseError {
    InvalidChecksum(ChecksumError),
    InvalidLength(Vec<u8>),
}

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
    ingress_expiry_duration: Duration
) -> Result<String, String> {
    let to_account_identifier_crc = AccountIdentifierWithCRC::new(
        &to_principal,
        &to_subaccount
    );
    let to = AccountIdentifier::from_hex(
        to_account_identifier_crc.to_hex().as_ref()
    )
        .map_err(|e| e.to_string())?;
    let now = SystemTime::now();
    let send_args = SendArgs {
        memo: Memo(memo),
        amount: Tokens::from_e8s(amount),
        fee: Tokens::from_e8s(fee),
        from_subaccount: Some(from_subaccount),
        to,
        created_at_time: Some(Timestamp {
            timestamp_nanos: now
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
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


    let canister_id = Principal::from_text(canister_id)
        .map_err(|e| e.to_string())?;

    sign_implementation(
        canister_id,
        method_name,
        send_args,
        secret_key,
        sender,
        ic_url,
        ingress_expiry
    )
}

fn sign_implementation(
    canister_id: Principal,
    method_name: String,
    send_args: SendArgs,
    secret_key: &[u8],
    sender: Principal,
    ic_url: String,
    ingress_expiry: Duration, /*Duration::from_secs(5 * 60)*/
) -> Result<String, String> {
    let arg = send_request_proto::into_bytes(send_args.clone())?;
    let envelope = EnvelopeContent::Call {
        canister_id,
        method_name: method_name.clone(),
        arg: arg.clone(),
        nonce: None,
        sender,
        ingress_expiry: ingress_expiry.as_nanos() as u64,
    };
    let request_id = envelope.to_request_id();
    let secret_key = SecretKey::from_slice(secret_key)
        .map_err(|_| "Error extracting secret key".to_string())?;
    let identity = Box::new(
        Secp256k1Identity::from_private_key(secret_key)
    );

    let agent = Agent::builder()
        .with_url(ic_url)
        .with_ingress_expiry(Some(ingress_expiry))
        .with_boxed_identity(identity)
        .build()
        .map_err(|err| err.to_string())?;

    let signed_update = UpdateBuilder::new(
        &agent,
        canister_id,
        method_name
    )
        .with_arg(arg)
        .expire_after(ingress_expiry)
        .sign()
        .map_err(|e| e.to_string())?;

    let ingress = Ingress {
        call_type: "update".to_string(),
        request_id: Some(request_id.into()),
        content: hex::encode(signed_update.signed_update.clone()),
        role: Some("nns:ledger".to_string()),
    };

    let request_status_signed = agent
        .sign_request_status(canister_id, request_id)
        .map_err(|_| "Error while signing requst status")?;
    let request_status = RequestStatus {
        canister_id: canister_id.to_string(),
        request_id: request_id.into(),
        content: hex::encode(request_status_signed.signed_request_status),
    };
    let message = IngressWithRequestId {
        ingress,
        request_status,
    };
    Ok(serde_json::to_string(&message)
        .map_err(|_|"error during json serialization")?)
}

fn sign_secp256k1(
    content: &[u8],
    secret_key_slice: &[u8]
) -> Result<Vec<u8>, String> {
    let secret_key = SecretKey::from_slice(secret_key_slice)
        .map_err(|_| "Error extracting secret key".to_string())?;
    let signing_key: ecdsa::SigningKey = secret_key.into();
    let (ecdsa_sig,
        _recovery_id) = signing_key.sign(content);
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
    use crate::sign_transfer_sendpb::{
        AccountIdentifier,
        sign_secp256k1,
        sign_transfer
    };

    use ic_agent::{
        identity::{
            Secp256k1Identity,
        },
        Identity,
        agent::EnvelopeContent
    };

    use k256::{
        ecdsa,
        pkcs8,
        pkcs8::{
            Document,
            EncodePublicKey
        },
        PublicKey,
        SecretKey
    };
    use candid::Principal;
    use std::time::Duration;
    use ic_ledger_types::{
        Subaccount,
        AccountIdentifier as AccountIdentifierWithCRC
    };

    pub const IC_URL: &str = "https://ic0.app";
    pub const LEDGER_CANISTER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
    pub const METHOD_NAME: &str = "send_pb";
    pub const ECDSA_SECP256K1: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIPsTPMsLBgjMyv36kvCrb2rOP8sH1+76PRzAWuycKVaToAcGBSuBBAAK
oUQDQgAE/WCEaPgIP8m/zQULrL1htecNlTLeKcWsnnwb1MmTXGkjiz6CWGW9z83n
EaEbktCSDAPeCb4KB6/L3XBACX3YCA==
-----END EC PRIVATE KEY-----";

    pub fn get_secp256k1_secret_key() -> Result<SecretKey, String> {
        SecretKey::from_sec1_pem(ECDSA_SECP256K1)
            .map_err(|_| pkcs8::Error::KeyMalformed.to_string())
    }

    pub fn get_secp256k1_secret_key_bytes() -> Result<Vec<u8>, String>{
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
        hex::encode(public_key_der)
    }

    pub fn get_secp256k1_signing_key_bytes(secret_key: SecretKey) -> Vec<u8>{
        let signing_key: ecdsa::SigningKey = secret_key.into();
        signing_key.to_bytes().to_vec()
    }

    pub fn get_principal_from_text(principal_text: &str) -> Result<Principal, String> {
        Principal::from_text(principal_text)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn test_secp256k_key_bytes() -> Result<(), String> {
        let data: [u8; 16] = [1; 16];
        let identity = Secp256k1Identity::from_pem(
            ECDSA_SECP256K1.as_bytes()
        )
            .map_err(|_| "Error reading pem bytes")?;

        let message = EnvelopeContent::Call {
            nonce: None,
            ingress_expiry: 0,
            sender: identity.sender().unwrap(),
            canister_id: "bkyz2-fmaaa-aaaaa-qaaaq-cai".parse().unwrap(),
            method_name: "greet".to_string(),
            arg: vec![1,1,1,1,1,1,1,1],
        };
        let result1 = identity
            .sign(&message)?
            .signature
            .ok_or("Invalid signature in result1")?;

        let content = message.to_request_id().signable();
        let secret_key = get_secp256k1_secret_key_bytes()?;
        let result2 = sign_secp256k1(
            content.as_slice(),
            secret_key.as_slice())?;
        assert_eq!(&result1[..], &result2[..]);
        Ok(())
    }

    #[test]
    pub fn test_call_sign() -> Result<(), String>{
        let ingress_expiry_duration = Duration::from_secs(5 * 60);
        let canister_id = Principal::from_text(LEDGER_CANISTER)
            .map_err(|e| e.to_string())?;
        let from_subaccount = Subaccount([0;32]);
        let from_principal = get_principal_from_text(
            "meky5-ylcvy-7z53d-oqtoh-yxmvs-akp7v-p2ugh-swlsw-tpdw5-jl6wg-nqe"
        )?;
        let from_account_identifier_crc = AccountIdentifierWithCRC::new(&from_principal, &from_subaccount);
        let from = AccountIdentifier::from_hex(
            from_account_identifier_crc.to_hex().as_ref()
        )
            .map_err(|e| e.to_string())?;
        let secret_key = get_secp256k1_secret_key_bytes()?;
        let to_principal = get_principal_from_text(
            "22ytb-hyvdp-o2eb4-k2c2v-nyomn-lzpsu-lbhc2-iw3c3-uouvh-7ecjo-5qe"
        )?;
        let to_subaccount = Subaccount([0; 32]);

        let transfer: String = sign_transfer(
            0,
            100000,
            10000,
            from_subaccount,
            from_principal,
            to_principal,
            to_subaccount,
            secret_key,
            ingress_expiry_duration
        )?;
        Ok(())
    }
}
