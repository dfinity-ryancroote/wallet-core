use std::time::Duration;

use tw_keypair::ecdsa::secp256k1::PrivateKey;

use crate::{
    address::AccountIdentifier,
    protocol::{get_ingress_expiry, identity::Identity, principal::Principal, rosetta},
    transactions::proto::ic_ledger::pb::v1::{
        AccountIdentifier as ProtoAccountIdentifier, Memo, Payment, SendRequest, TimeStamp, Tokens,
    },
};

use super::{create_read_state_envelope, create_update_envelope, SignTransactionError};

/// Arguments to be used with [transfer] to create a signed transaction enveloper pair.
#[derive(Clone, Debug)]
pub struct TransferArgs {
    /// The memo field is used as a method to help identify the transaction.
    pub memo: u64,
    /// The amount of ICP to send as e8s.
    pub amount: u64,
    /// The maximum fee will to be paid to complete the transfer.
    /// If not provided, the minimum fee will be applied to the transaction. Currently 10_000 e8s (0.00010000 ICP).
    pub max_fee: Option<u64>,
    /// The address to send the amount to.
    pub to: String,
    /// The current timestamp in nanoseconds.
    pub current_timestamp_nanos: u64,
}

impl TryFrom<TransferArgs> for SendRequest<'_> {
    type Error = SignTransactionError;

    fn try_from(args: TransferArgs) -> Result<Self, Self::Error> {
        let current_timestamp_duration = Duration::from_nanos(args.current_timestamp_nanos);
        let timestamp_nanos = current_timestamp_duration.as_nanos() as u64;

        let to_account_identifier = AccountIdentifier::from_hex(&args.to)
            .map_err(|_| SignTransactionError::InvalidToAddress)?;
        let to_hash = to_account_identifier.as_ref().to_vec();

        let request = Self {
            memo: Some(Memo { memo: args.memo }),
            payment: Some(Payment {
                receiver_gets: Some(Tokens { e8s: args.amount }),
            }),
            max_fee: args.max_fee.map(|fee| Tokens { e8s: fee }),
            from_subaccount: None,
            to: Some(ProtoAccountIdentifier {
                hash: to_hash.into(),
            }),
            created_at: None,
            created_at_time: Some(TimeStamp { timestamp_nanos }),
        };
        Ok(request)
    }
}

/// The endpoint on the ledger canister that is used to make transfers.
const METHOD_NAME: &str = "send_pb";

/// Given a secp256k1 private key, the canister ID of an ICP-based ledger canister, and the actual transfer args,
/// this function creates a signed transaction to be sent to a Rosetta API node.
pub fn transfer(
    private_key: PrivateKey,
    canister_id: Principal,
    args: TransferArgs,
) -> Result<rosetta::SignedTransaction, SignTransactionError> {
    if args.amount < 1 {
        return Err(SignTransactionError::InvalidAmount);
    }

    let current_timestamp_duration = Duration::from_nanos(args.current_timestamp_nanos);
    let ingress_expiry = get_ingress_expiry(current_timestamp_duration);
    let identity = Identity::new(private_key);

    // Encode the arguments for the ledger `send_pb` endpoint.
    let send_request = SendRequest::try_from(args)?;
    let arg =
        tw_proto::serialize(&send_request).map_err(|_| SignTransactionError::EncodingArgsFailed)?;
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
