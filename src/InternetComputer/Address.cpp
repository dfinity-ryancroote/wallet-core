// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Address.h"
#include "Base32.h"
#include "Crc.h"
#include "Hash.h"
#include "HexCoding.h"
#include <algorithm>
#include <iostream>
#include <numeric>
#include <string>

namespace TW::InternetComputer {

bool Address::isValid(const std::string& string) {
    return Rust::tw_internetcomputer_is_address_valid(string.c_str());
}

Address::Address(const std::string& string) {
    if (!isValid(string)) {
        throw std::invalid_argument("Invalid address string");
    }

    str = string;
}

Address::Address(const PublicKey& publicKey) {
    Rust::CByteArrayResultWrapper res = Rust::tw_internetcomputer_encode_public_key_to_principal(publicKey.bytes.data(), publicKey.bytes.size());
    const auto principal = res.unwrap_or_default().data;
    auto address_res = Rust::tw_internetcomputer_principal_to_account_identifer(principal.data(), principal.size());

    std::string address(address_res);
    Rust::free_string(address_res);
    str = address;
}

std::string Address::string() const {
    return str;
}

} // namespace TW::InternetComputer
