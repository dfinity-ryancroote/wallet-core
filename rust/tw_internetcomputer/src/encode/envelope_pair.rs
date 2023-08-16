use std::time::Duration;

use candid::Principal;

use crate::interface_spec::envelope::{Envelope, EnvelopeContent};
use crate::interface_spec::get_ingress_expiry;
use crate::rosetta::{self, EnvelopePair};
use crate::sign::SignTransferError;

pub fn encode_envolope_pair(
    sender: Vec<u8>,
    der_encoded_public_key: Vec<u8>,
    canister_id: Vec<u8>,
    method_name: &str,
    arg: Vec<u8>,
    update_request_id: Vec<u8>,
    update_request_signature: Vec<u8>,
    read_state_request_signature: Vec<u8>,
    current_timestamp_secs: u64,
) -> Result<Vec<u8>, SignTransferError> {
    let sender = Principal::from_slice(&sender);
    let canister_id = Principal::from_slice(&canister_id);
    let current_timestamp_duration = Duration::from_secs(current_timestamp_secs);
    let ingress_expiry = get_ingress_expiry(current_timestamp_duration);

    let call_envelope = call_envelope(
        sender.clone(),
        canister_id,
        method_name,
        arg,
        ingress_expiry,
        update_request_signature,
        der_encoded_public_key.clone(),
    );

    let read_state_envelope = read_state_envelope(
        sender,
        update_request_id,
        ingress_expiry,
        der_encoded_public_key,
        read_state_request_signature,
    );

    let pair = EnvelopePair::new(call_envelope, read_state_envelope);
    let request: rosetta::Request = (rosetta::RequestType::Send, vec![pair]);
    let signed_transaction: rosetta::SignedTransaction = vec![request];

    serde_cbor::to_vec(&signed_transaction)
        .map_err(|_| SignTransferError::EncodingSignedTransactionFailed)
}

fn call_envelope(
    sender: Principal,
    canister_id: Principal,
    method_name: &str,
    arg: Vec<u8>,
    ingress_expiry: u64,
    update_request_signature: Vec<u8>,
    der_encoded_public_key: Vec<u8>,
) -> Envelope {
    let content = EnvelopeContent::Call {
        nonce: None, //TODO: do we need the nonce?
        ingress_expiry,
        sender,
        canister_id,
        method_name: method_name.to_string(),
        arg,
    };

    Envelope {
        content,
        sender_pubkey: Some(der_encoded_public_key),
        sender_sig: Some(update_request_signature),
    }
}

fn read_state_envelope(
    sender: Principal,
    update_request_id: Vec<u8>,
    ingress_expiry: u64,
    der_encoded_public_key: Vec<u8>,
    read_state_signature: Vec<u8>,
) -> Envelope {
    let content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender,
        paths: vec![vec!["request_status".into(), update_request_id.into()]],
    };

    Envelope {
        content,
        sender_pubkey: Some(der_encoded_public_key),
        sender_sig: Some(read_state_signature),
    }
}
