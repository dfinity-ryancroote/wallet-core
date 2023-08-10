use std::time::Duration;

use candid::CandidType;
use ic_ledger_types::{AccountIdentifier, Memo, Subaccount, Timestamp, Tokens};
use serde::{Deserialize, Serialize};
use tw_encoding::hex;

use crate::sign_transfer_sendpb::METHOD_NAME;

use super::{
    identity::Identity,
    interface_spec::{
        envelope::{Envelope, EnvelopeContent},
        request_id::{self, RequestId},
    },
    proto, rosetta,
};

// The fee for a transfer is the always 10_000 e8s.
const FEE: Tokens = Tokens::from_e8s(10_000);

#[derive(Serialize, Deserialize, CandidType, Clone, Hash, Debug, PartialEq, Eq)]
pub struct SendArgs {
    pub memo: Memo,
    pub amount: Tokens,
    pub fee: Tokens,
    pub from_subaccount: Option<Subaccount>,
    pub to: AccountIdentifier,
    pub created_at_time: Option<Timestamp>,
}

pub fn transfer(
    identity: Identity,
    to_account_identifier: AccountIdentifier,
    amount: u64,
    memo: u64,
    current_timestamp_secs: u64,
) -> Result<String, String> {
    let current_timestamp_nanos = Duration::from_secs(current_timestamp_secs).as_nanos() as u64;

    let args = SendArgs {
        memo: Memo(memo),
        amount: Tokens::from_e8s(amount),
        fee: FEE,
        from_subaccount: None, // Uses the default subaccount.
        to: to_account_identifier,
        created_at_time: Some(Timestamp {
            timestamp_nanos: current_timestamp_nanos,
        }),
    };
    let arg = proto::into_bytes(args)?;

    // Create the update envelope.
    let update_envelope = create_update_envelope(&identity, arg, current_timestamp_nanos)?;
    let request_id = update_envelope.content.to_request_id();

    // Create the read state envelope.
    let read_state_envelope =
        create_read_state_envelope(&identity, request_id, current_timestamp_nanos)?;

    // Create a new EnvelopePair with the update call and read_state envelopes.
    let envelope_pair = rosetta::EnvelopePair::new(update_envelope, read_state_envelope);

    // Create a signed transaction containing the envelope pair.
    let request: rosetta::Request = (rosetta::RequestType::Send, vec![envelope_pair]);
    let signed_transaction: rosetta::SignedTransaction = vec![request];
    // Encode the signed transaction.
    let cbor_encoded_signed_transaction = serde_cbor::to_vec(&signed_transaction)
        .map_err(|e| format!("Failed to serialize signed transaction: {}", e))?;
    let hex_encoded_cbor = hex::encode(&cbor_encoded_signed_transaction, false);

    Ok(hex_encoded_cbor)
}

fn create_update_envelope(
    identity: &Identity,
    arg: Vec<u8>,
    ingress_expiry: u64,
) -> Result<Envelope, String> {
    let sender = identity.sender();
    let content = EnvelopeContent::Call {
        nonce: None, //TODO: do we need the nonce?
        ingress_expiry,
        sender,
        canister_id: ic_ledger_types::MAINNET_LEDGER_CANISTER_ID,
        method_name: METHOD_NAME.to_string(),
        arg,
    };

    let request_id = content.to_request_id();
    let signature = identity.sign(request_id::make_sig_data(&request_id))?;

    let env = Envelope {
        content,
        sender_pubkey: Some(signature.public_key),
        sender_sig: Some(signature.signature),
    };
    Ok(env)
}

fn create_read_state_envelope(
    identity: &Identity,
    request_id: RequestId,
    ingress_expiry: u64,
) -> Result<Envelope, String> {
    let sender = identity.sender();

    let content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender,
        paths: vec![vec![
            "request_status".into(),
            request_id.0.as_slice().into(),
        ]],
    };

    let request_id = content.to_request_id();
    let signature = identity.sign(request_id::make_sig_data(&request_id))?;

    let env = Envelope {
        content,
        sender_pubkey: Some(signature.public_key),
        sender_sig: Some(signature.signature),
    };
    Ok(env)
}
