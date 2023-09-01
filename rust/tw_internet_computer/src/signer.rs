// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use std::marker::PhantomData;

use tw_coin_entry::{
    error::{SigningError, SigningResult},
    signing_output_error,
};
use tw_keypair::ecdsa::secp256k1;
use tw_proto::{Common::Proto::SigningError as CommonError, InternetComputer::Proto};

use crate::{
    context::{CanisterId, InternetComputerContext},
    protocol::{identity, principal::Principal},
    transactions::{self, sign_transaction},
};

impl From<transactions::SignTransactionError> for SigningError {
    fn from(error: transactions::SignTransactionError) -> Self {
        match error {
            transactions::SignTransactionError::InvalidArguments => {
                SigningError(CommonError::Error_invalid_params)
            },
            transactions::SignTransactionError::Identity(identity_error) => match identity_error {
                identity::SigningError::Failed(_) => SigningError(CommonError::Error_signing),
            },
            transactions::SignTransactionError::EncodingArgsFailed => {
                SigningError(CommonError::Error_internal)
            },
            transactions::SignTransactionError::InvalidToAccountIdentifier => {
                SigningError(CommonError::Error_invalid_address)
            },
        }
    }
}

pub struct Signer<Context: InternetComputerContext> {
    _phantom: PhantomData<Context>,
}

impl<Context: InternetComputerContext> Signer<Context> {
    #[inline]
    pub fn sign_proto(input: Proto::SigningInput<'_>) -> Proto::SigningOutput<'static> {
        Self::sign_proto_impl(input)
            .unwrap_or_else(|e| signing_output_error!(Proto::SigningOutput, e))
    }

    fn sign_proto_impl(
        input: Proto::SigningInput<'_>,
    ) -> SigningResult<Proto::SigningOutput<'static>> {
        let private_key = secp256k1::PrivateKey::try_from(input.private_key.as_ref())?;

        let Some(ref transaction) = input.transaction else {
            return Err(SigningError(CommonError::Error_invalid_params));
        };

        let canister_id = Self::canister_id();
        let signed_transaction =
            sign_transaction(private_key, canister_id, &transaction.transaction_oneof)
                .map_err(SigningError::from)?;

        let cbor_encoded_signed_transaction = tw_cbor::serialize(&signed_transaction)
            .map_err(|_| SigningError(CommonError::Error_internal))?;

        Ok(Proto::SigningOutput {
            signed_transaction: cbor_encoded_signed_transaction.into(),
            ..Proto::SigningOutput::default()
        })
    }

    #[inline]
    fn canister_id() -> Principal {
        Context::Canister::principal_id()
    }
}
