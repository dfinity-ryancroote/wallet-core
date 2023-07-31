// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Address.h"
#include "Crc.h"
#include "HexCoding.h"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <numeric>
#include <string>

namespace TW::InternetComputer {

bool Address::isValid(const std::string& string) {
    if (string.length() != 64) {
        return false;
    }
    const TW::Data bytes = parse_hex(string);
    if (bytes.empty()) {
        return false;
    }

    const auto expected_checksum = Crc::crc32(std::vector<uint8_t>(bytes.begin() + 4, bytes.end()));
    uint32_t address_checksum = std::accumulate(bytes.begin(), bytes.begin() + 4, 0, [](uint32_t acc, uint32_t val) {
        return acc * 256 + val;
    });

    return expected_checksum == address_checksum;
}

Address::Address(const std::string& string) {
    // TODO: Finalize implementation

    if (!isValid(string)) {
        throw std::invalid_argument("Invalid address string");
    }

    bytes = parse_hex(string);
}

Address::Address(const PublicKey& publicKey) {
    // TODO: Finalize implementation
}

std::string Address::string() const {
    // TODO: Finalize implementation
    return hex(bytes);
}

} // namespace TW::InternetComputer
