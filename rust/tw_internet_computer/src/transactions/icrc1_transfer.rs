use std::time::Duration;

use candid::{CandidType, Nat};
use tw_keypair::ecdsa::secp256k1::PrivateKey;

use crate::{
    icrc::address::{IcrcAccount, Subaccount},
    protocol::{get_ingress_expiry, identity::Identity, principal::Principal, rosetta},
};

use super::{create_read_state_envelope, create_update_envelope, SignTransactionError};

const METHOD_NAME: &str = "icrc1_transfer";

#[derive(Debug, CandidType)]
pub struct TransferArgs {
    pub from_subaccount: Option<Subaccount>,
    pub to: IcrcAccount,
    pub amount: Nat,
    pub fee: Option<Nat>,
    pub memo: Option<Vec<u8>>,
    pub created_at_time: Option<u64>,
}

pub fn icrc1_transfer(
    private_key: PrivateKey,
    canister_id: Principal,
    args: TransferArgs,
) -> Result<rosetta::SignedTransaction, SignTransactionError> {
    if args.amount < 1u8 {
        return Err(SignTransactionError::InvalidAmount);
    }

    let Some(created_at_time) = args.created_at_time else {
        return Err(SignTransactionError::InvalidArguments);
    };

    let current_timestamp_duration = Duration::from_nanos(created_at_time);
    let ingress_expiry = get_ingress_expiry(current_timestamp_duration);
    let identity = Identity::new(private_key);

    // Encode the arguments into candid.
    let Ok(arg) = candid::encode_one(&args) else {
        return Err(SignTransactionError::EncodingArgsFailed);
    };

    // Create the update envelope.
    let (request_id, update_envelope) =
        create_update_envelope(&identity, canister_id, METHOD_NAME, arg, ingress_expiry)?;

    // Create the read state envelope.
    let (_, read_state_envelope) =
        create_read_state_envelope(&identity, request_id, ingress_expiry)?;

    // Create a new EnvelopePair with the update call and read_state envelopes.
    let envelope_pair = rosetta::EnvelopePair::new(update_envelope, read_state_envelope)
        .map_err(|_| SignTransactionError::InvalidEnvelopePair)?;

    // Create a signed transaction containing the envelope pair.
    let request: rosetta::Request = (rosetta::RequestType::Send, vec![envelope_pair]);
    Ok(vec![request])
}
