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

#[cfg(test)]
mod test {

    use std::str::FromStr;

    use tw_encoding::hex;

    use super::*;

    const CKBTC_CANISTER_ID: Principal =
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x00, 0x06, 0x01, 0x01]);
    const PRIVATE_KEY_HEX: &str =
        "227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be";
    const SIGNED_TRANSACTION: &str = "81826b5452414e53414354494f4e81a266757064617465a367636f6e74656e74a66c726571756573745f747970656463616c6c6e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d026b63616e69737465725f69644a000000000230000601016b6d6574686f645f6e616d656e69637263315f7472616e736665726361726758934449444c066c06fbca0101c6fcb60204ba89e5c20402a2de94eb060282f3f3910c05d8a38ca80d7d6c02b3b0dac30368ad86ca8305026e036d7b6e7d6e780100011db56bf994b37ae8e79f5ce000be1727a6060ae4eef24736b7cc999c3c0201200000000000000000000000000000000000000000000000000000000000000001000101a000010088b2343a297a1780c2d72f6d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018f4187d18bc18d818aa1883182618aa182c184f18a8185a18b50511187b18eb18fb185f0c18741218331836183a18dd18cf189b18ed18f418220e184d1842189b1898121857185d188718c418df18c3188b18b418c0185818201843182f18f4182e185a18f618bf16182a1845183c18fd184e0618fe18586a726561645f7374617465a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d0265706174687381824e726571756573745f73746174757358204dfea0adbdda4c3b5145e162a91811930db13d8949fe36acb9759a934df147a96d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018cb1851186a18e7186518d3188e1846185a0b1838185a18bd182918cd187b18a418a718e618a018b6183a18c118cd18de18ae185004189f18cd189618dc183e18da1821011820188b181a18f9189c189318741881185b18fa18e9187a18dc18db1518e10d18d1187118ef18360d182418fb181c1889185c188a";

    fn make_transfer_args() -> TransferArgs {
        let current_timestamp_nanos = Duration::from_secs(1_691_709_940).as_nanos() as u64;
        let to = IcrcAccount::from_str(
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1",
        )
        .unwrap();
        TransferArgs {
            from_subaccount: None,
            to,
            amount: Nat::from(100_000_000),
            fee: None,
            memo: Some(hex::decode("a0").unwrap()),
            created_at_time: Some(current_timestamp_nanos),
        }
    }

    #[test]
    fn transfer_successful() {
        let private_key = PrivateKey::try_from(PRIVATE_KEY_HEX).unwrap();
        let transfer_args = make_transfer_args();

        let signed_transaction =
            icrc1_transfer(private_key, CKBTC_CANISTER_ID, transfer_args).unwrap();
        // Encode the signed transaction.
        let cbor_encoded_signed_transaction = tw_cbor::serialize(&signed_transaction).unwrap();
        let hex_encoded_signed_transaction = hex::encode(&cbor_encoded_signed_transaction, false);
        assert_eq!(hex_encoded_signed_transaction, SIGNED_TRANSACTION);
    }

    #[test]
    fn transfer_invalid_amount() {
        let private_key = PrivateKey::try_from(PRIVATE_KEY_HEX).unwrap();
        let mut transfer_args = make_transfer_args();
        transfer_args.amount = Nat::from(0);

        let signed_transaction = icrc1_transfer(private_key, CKBTC_CANISTER_ID, transfer_args);
        assert!(matches!(
            signed_transaction,
            Err(SignTransactionError::InvalidAmount)
        ));
    }
}
