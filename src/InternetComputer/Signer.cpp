// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "../PublicKey.h"

namespace TW::InternetComputer {

Proto::SigningOutput Signer::sign(const Proto::SigningInput& input) noexcept {
    Data privateKey = Data(input.private_key().begin(), input.private_key().end());

    Proto::SigningOutput output;

    auto transaction = input.transaction();

    switch (input.transaction().transaction_oneof_case()) {

    case Proto::Transaction::kTransfer:
    default:
        const auto transfer = input.transaction().transfer();
        output = signTransfer(privateKey, transfer);
        break;
    }

    return output;
}

Proto::SigningOutput Signer::signTransfer(const Data privateKey, const Proto::Transaction_Transfer& transfer) noexcept {
    auto output = Proto::SigningOutput();
    const auto to_account_identifier = transfer.to_account_identifier();
    const auto amount = transfer.amount();
    const auto memo = transfer.memo();
    const auto current_timestamp_secs = transfer.current_timestamp_secs();
    Rust::CByteArrayResultWrapper signed_transfer_result = Rust::tw_internetcomputer_sign_transfer(privateKey.data(), privateKey.size(), to_account_identifier.c_str(), amount, memo, current_timestamp_secs);
    if (signed_transfer_result.isOk()) {
        const auto signed_transaction = signed_transfer_result.unwrap_or_default();
        output.set_signed_transaction(signed_transaction.data.data(), signed_transaction.data.size());
    } else {
        output.set_error(TW::Common::Proto::SigningError::Error_general);
    }

    return output;
}

} // namespace TW::InternetComputer
