// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "Data.h"
#include "PublicKey.h"

#include <string>

namespace TW::InternetComputer {

class Address {
public:
    std::string str;
    // TODO: Complete class definition

    /// Determines whether a string makes a valid address.
    static bool isValid(const std::string& string);

    /// Initializes a InternetComputer address with a string representation.
    explicit Address(const std::string& string);

    /// Initializes a InternetComputer address with a public key.
    explicit Address(const PublicKey& publicKey);

    /// Returns a string representation of the address.
    std::string string() const;
};

inline bool operator==(const Address& lhs, const Address& rhs) {
    return lhs.string() == rhs.string();
}

} // namespace TW::InternetComputer
