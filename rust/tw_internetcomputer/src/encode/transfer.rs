use std::time::Duration;

use ic_ledger_types;
use prost;
use prost::Message;

/// The fee for a transfer is always 10_000 e8s.
const FEE: ic_ledger_types::Tokens = ic_ledger_types::Tokens::from_e8s(10_000);

pub fn encode_transfer_args(
    to_account_identifier: &str,
    amount: u64,
    memo: u64,
    current_timestamp_secs: u64,
) -> Result<Vec<u8>, String> {
    let timestamp_nanos = Duration::from_secs(current_timestamp_secs).as_nanos() as u64;

    SendArgs {
        memo: ic_ledger_types::Memo(memo),
        amount: ic_ledger_types::Tokens::from_e8s(amount),
        fee: FEE,
        to: ic_ledger_types::AccountIdentifier::from_hex(to_account_identifier)?,
        created_at_time: Some(ic_ledger_types::Timestamp { timestamp_nanos }),
    }
    .to_proto()
}

#[derive(Clone, Debug)]
struct SendArgs {
    memo: ic_ledger_types::Memo,
    amount: ic_ledger_types::Tokens,
    fee: ic_ledger_types::Tokens,
    to: ic_ledger_types::AccountIdentifier,
    created_at_time: Option<ic_ledger_types::Timestamp>,
}

impl SendArgs {
    fn to_proto(self) -> Result<Vec<u8>, String> {
        let proto_type = into_proto(self);
        let mut buf = Vec::with_capacity(proto_type.encoded_len());
        proto_type.encode(&mut buf).map_err(|e| e.to_string())?;
        Ok(buf)
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct AccountIdentifier {
    /// Can contain either:
    ///   * the 32 byte identifier (4 byte checksum + 28 byte hash)
    ///   * the 28 byte hash
    #[prost(bytes = "vec", tag = "1")]
    hash: prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Subaccount {
    #[prost(bytes = "vec", tag = "1")]
    sub_account: prost::alloc::vec::Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Memo {
    #[prost(uint64, tag = "1")]
    memo: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Tokens {
    #[prost(uint64, tag = "1")]
    e8s: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Payment {
    #[prost(message, optional, tag = "1")]
    receiver_gets: ::core::option::Option<Tokens>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct BlockIndex {
    #[prost(uint64, tag = "1")]
    height: u64,
}
#[derive(Clone, PartialEq, prost::Message)]
struct TimeStamp {
    #[prost(uint64, tag = "1")]
    timestamp_nanos: u64,
}
/// Make a payment
#[derive(Clone, PartialEq, prost::Message)]
struct SendRequest {
    #[prost(message, optional, tag = "1")]
    memo: ::core::option::Option<Memo>,
    #[prost(message, optional, tag = "2")]
    payment: ::core::option::Option<Payment>,
    #[prost(message, optional, tag = "3")]
    max_fee: ::core::option::Option<Tokens>,
    #[prost(message, optional, tag = "4")]
    from_subaccount: ::core::option::Option<Subaccount>,
    #[prost(message, optional, tag = "5")]
    to: ::core::option::Option<AccountIdentifier>,
    #[prost(message, optional, tag = "6")]
    created_at: ::core::option::Option<BlockIndex>,
    #[prost(message, optional, tag = "7")]
    created_at_time: ::core::option::Option<TimeStamp>,
}

fn tokens_into_proto(tokens: ic_ledger_types::Tokens) -> Tokens {
    Tokens { e8s: tokens.e8s() }
}

fn timestamp_into_proto(ts: ic_ledger_types::Timestamp) -> TimeStamp {
    TimeStamp {
        timestamp_nanos: ts.timestamp_nanos,
    }
}

fn into_proto(args: SendArgs) -> SendRequest {
    let SendArgs {
        memo,
        amount,
        fee,
        to,
        created_at_time,
    } = args;
    let amount = tokens_into_proto(amount);
    let payment = Some(Payment {
        receiver_gets: Some(amount),
    });

    SendRequest {
        memo: Some(Memo { memo: memo.0 }),
        payment,
        max_fee: Some(tokens_into_proto(fee)),
        from_subaccount: None,
        to: Some(to).map(|ai| AccountIdentifier {
            hash: ai.as_ref().to_vec(),
        }),
        created_at: None,
        created_at_time: created_at_time.map(timestamp_into_proto),
    }
}
