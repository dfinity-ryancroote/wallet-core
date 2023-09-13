pub mod icrc1_transfer;
pub mod transfer;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));
}

use std::str::FromStr;

use ic_certification::Label;
use tw_keypair::ecdsa::secp256k1::PrivateKey;
use tw_proto::InternetComputer::Proto::mod_Transaction::OneOftransaction_oneof as Tx;

use crate::{
    icrc::address::IcrcAccount,
    protocol::{
        envelope::{Envelope, EnvelopeContent},
        identity::{self, Identity},
        principal::Principal,
        request_id::RequestId,
        rosetta,
    },
};

#[derive(Debug)]
pub enum SignTransactionError {
    InvalidAmount,
    InvalidArguments,
    Identity(identity::SigningError),
    EncodingArgsFailed,
    InvalidToAddress,
    InvalidEnvelopePair,
}

pub fn sign_transaction(
    private_key: PrivateKey,
    canister_id: Principal,
    transaction: &Tx,
) -> Result<rosetta::SignedTransaction, SignTransactionError> {
    match transaction {
        Tx::transfer(transfer_args) => transfer::transfer(
            private_key,
            canister_id,
            transfer::TransferArgs {
                memo: transfer_args.memo,
                amount: transfer_args.amount,
                max_fee: None,
                to: transfer_args.to_account_identifier.to_string(),
                current_timestamp_nanos: transfer_args.current_timestamp_nanos,
            },
        ),
        Tx::icrc1_transfer(icrc1_transfer_args) => icrc1_transfer::icrc1_transfer(
            private_key,
            canister_id,
            icrc1_transfer::TransferArgs {
                from_subaccount: None, // Use the default subaccount only
                to: IcrcAccount::from_str(&icrc1_transfer_args.to_icrc_account)
                    .map_err(|_| SignTransactionError::InvalidToAddress)?,
                amount: candid::Nat::from(icrc1_transfer_args.amount),
                fee: None, // Pay the minimum fee
                memo: Some(icrc1_transfer_args.memo.to_vec()),
                created_at_time: Some(icrc1_transfer_args.created_at_time_nanos),
            },
        ),
        Tx::None => Err(SignTransactionError::InvalidArguments),
    }
}

#[inline]
fn create_update_envelope(
    identity: &Identity,
    canister_id: Principal,
    method_name: &str,
    arg: Vec<u8>,
    ingress_expiry: u64,
) -> Result<(RequestId, Envelope), SignTransactionError> {
    let sender = identity.sender();
    let content = EnvelopeContent::Call {
        nonce: None,
        ingress_expiry,
        sender,
        canister_id,
        method_name: method_name.to_string(),
        arg,
    };

    let request_id = RequestId::from(&content);
    let signature = identity
        .sign(request_id.sig_data())
        .map_err(SignTransactionError::Identity)?;

    let env = Envelope {
        content,
        sender_pubkey: Some(signature.public_key),
        sender_sig: Some(signature.signature),
    };
    Ok((request_id, env))
}

#[inline]
fn create_read_state_envelope(
    identity: &Identity,
    update_request_id: RequestId,
    ingress_expiry: u64,
) -> Result<(RequestId, Envelope), SignTransactionError> {
    let sender = identity.sender();

    let content = EnvelopeContent::ReadState {
        ingress_expiry,
        sender,
        paths: vec![vec![
            Label::from("request_status"),
            Label::from(update_request_id.0.as_slice()),
        ]],
    };

    let request_id = RequestId::from(&content);
    let signature = identity
        .sign(request_id.sig_data())
        .map_err(SignTransactionError::Identity)?;

    let env = Envelope {
        content,
        sender_pubkey: Some(signature.public_key),
        sender_sig: Some(signature.signature),
    };
    Ok((request_id, env))
}
