use std::time::Duration;

use candid::CandidType;
use ic_ledger_types::{AccountIdentifier, Memo, Subaccount, Timestamp, Tokens};
use serde::{Deserialize, Serialize};

use crate::sign_transfer_sendpb::METHOD_NAME;

use super::{
    identity::Identity,
    interface_spec::envelope::{Envelope, EnvelopeContent},
    proto,
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
    amount: u64,
    memo: u64,
    to_account_identifier: AccountIdentifier,
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
    create_update_envelope(&identity, arg, current_timestamp_nanos);

    // Create the read state envelope.

    // Create a new EnvelopePair with the update call and read_state envelopes.
    // Create a signed transaction containing the envelope pair.
    // Encode the signed transaction.
    Ok(String::from(""))
}

fn create_update_envelope(identity: &Identity, arg: Vec<u8>, ingress_expiry: u64) -> Envelope {
    let sender = identity.sender();
    let content = EnvelopeContent::Call {
        nonce: None, //TODO: do we need the nonce?
        ingress_expiry,
        sender,
        canister_id: ic_ledger_types::MAINNET_LEDGER_CANISTER_ID,
        method_name: METHOD_NAME.to_string(),
        arg,
    };

    let signature = identity.sign();

    Envelope {
        content,
        sender_pubkey: Some(signature.public_key),
        sender_sig: Some(signature.signature),
    }
}

fn create_read_state_envelope() -> Envelope {
    Envelope {
        content: todo!(),
        sender_pubkey: todo!(),
        sender_sig: todo!(),
    }
}

fn sign_envelope_content() {}
