// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Signer.h"
#include "Address.h"
#include "HexCoding.h"
#include "../PublicKey.h"
#include <iostream>

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
    const auto to_account_identifier = transfer.to_account_identifier();
    const auto amount = transfer.amount();
    const auto memo = transfer.memo();
    const auto current_timestamp_secs = transfer.current_timestamp_secs();

    const auto privkey = PrivateKey(privateKey);
    const auto pubkey = privkey.getPublicKey(TWPublicKeyTypeSECP256k1Extended);

    Rust::CByteArrayWrapper canister_id_wrapper = Rust::tw_internetcomputer_ledger_canister_id();
    const auto canister_id = canister_id_wrapper.data;

    Rust::CByteArrayResultWrapper der_encoded_public_key_result = Rust::tw_internetcomputer_der_encode_public_key(pubkey.bytes.data(), pubkey.bytes.size());
    const auto der_encoded_public_key = der_encoded_public_key_result.unwrap_or_default().data;
    std::cout << "DER encoded public key: " << hex(der_encoded_public_key, false) << std::endl;

    Rust::CByteArrayResultWrapper sender_result = Rust::tw_internetcomputer_encode_der_encoded_public_key_to_principal(der_encoded_public_key.data(), der_encoded_public_key.size());
    const auto sender = sender_result.unwrap_or_default().data;
    std::cout << "Sender principal: " << Rust::tw_encode_textual_principal(sender.data(), sender.size()) << std::endl;

    Rust::CByteArrayResultWrapper transfer_args_result = Rust::tw_internetcomputer_encode_transfer_args(to_account_identifier.c_str(), amount, memo, current_timestamp_secs);
    const auto transfer_args = transfer_args_result.unwrap_or_default().data;
    std::cout << "Transfer Args: " << hex(transfer_args, false) << std::endl;

    Rust::CByteArrayResultWrapper update_request_id_result = Rust::tw_internetcomputer_create_update_request_id(canister_id.data(), canister_id.size(), "send_pb", sender.data(), sender.size(), transfer_args.data(), transfer_args.size(), current_timestamp_secs);
    const auto update_request_id = update_request_id_result.unwrap_or_default().data;
    std::cout << "Update Request ID: " << hex(update_request_id, false) << std::endl;

    Rust::CByteArrayResultWrapper update_signature_data_result = Rust::tw_internetcomputer_get_signature_data_from_request_id(update_request_id.data());
    const auto update_signature_data = update_signature_data_result.unwrap_or_default().data;
    std::cout << "Update Signature Data: " << hex(update_signature_data, false) << std::endl;

    const auto update_request_signature = privkey.sign(update_signature_data, TWCurveSECP256k1);

    std::cout << "Update Signature: " << hex(update_request_signature, false) << std::endl;

    Rust::CByteArrayResultWrapper read_state_request_id_result = Rust::tw_internetcomputer_create_read_state_request_id(sender.data(), sender.size(), update_request_id.data(), current_timestamp_secs);
    const auto read_state_request_id = read_state_request_id_result.unwrap_or_default().data;
    std::cout << "Read State Request ID: " << hex(read_state_request_id, false) << std::endl;

    Rust::CByteArrayResultWrapper read_state_signature_data_result = Rust::tw_internetcomputer_get_signature_data_from_request_id(read_state_request_id.data());
    const auto read_state_signature_data = read_state_signature_data_result.unwrap_or_default().data;
    std::cout << "Read State Signature Data: " << hex(read_state_signature_data, false) << std::endl;

    const auto read_state_request_signature = privkey.sign(read_state_signature_data, TWCurveSECP256k1);
    std::cout << "Read State Signature: " << hex(read_state_request_signature, false) << std::endl;

    Rust::CByteArrayResultWrapper signed_transaction_result = Rust::tw_internetcomputer_encode_envelope_pair(
        sender.data(),
        sender.size(),
        der_encoded_public_key.data(),
        der_encoded_public_key.size(),
        canister_id.data(),
        canister_id.size(),
        "send_pb",
        transfer_args.data(),
        transfer_args.size(),
        update_request_id.data(),
        update_request_signature.data(),
        update_request_signature.size(),
        read_state_request_signature.data(),
        read_state_request_signature.size(),
        current_timestamp_secs);
    const auto signed_transaction = signed_transaction_result.unwrap_or_default().data;
    std::cout << "Signed Transaction: " << hex(signed_transaction, false) << std::endl;

    auto output = Proto::SigningOutput();
    return output;
}

Proto::SigningOutput Signer::handleSignTransferError(const TW::Rust::ErrorCode code) noexcept {
    auto output = Proto::SigningOutput();
    switch (code) {
    case 1:
        output.set_error(Common::Proto::SigningError::Error_invalid_private_key);
        break;
    case 2:
        output.set_error(Common::Proto::SigningError::Error_general);
        output.set_error_message("Failed to DER encode public key");
        break;
    case 3:
        output.set_error(Common::Proto::SigningError::Error_invalid_address);
        output.set_error_message("To address is invalid.");
        break;
    case 4:
    case 5:
        output.set_error(Common::Proto::SigningError::Error_general);
        output.set_error_message("Failed encoding arguments to send to node");
        break;
    case 6:
    case 7:
        output.set_error(Common::Proto::SigningError::Error_signing);
        output.set_error_message("Failed encoding arguments to send to node");
        break;
    default:
        output.set_error(Common::Proto::SigningError::Error_general);
        break;
    }

    return output;
}

} // namespace TW::InternetComputer
