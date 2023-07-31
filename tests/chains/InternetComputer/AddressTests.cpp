// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "HexCoding.h"
#include "InternetComputer/Address.h"
#include "PrivateKey.h"
#include "PublicKey.h"
#include <gtest/gtest.h>
#include <vector>

namespace TW::InternetComputer::tests {

TEST(InternetComputerAddress, Valid) {
    ASSERT_TRUE(Address::isValid("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e"));
    ASSERT_TRUE(Address::isValid("58B26ACE22A36A0011608A130E84C7CF34BA469C38D24CCF606152CE7DE91F4E"));
    ASSERT_TRUE(Address::isValid("1f1475dc61e2a6EABC70b98059940a41f8b7a6162d47bb1ca42e121a52270DF6"));
    ASSERT_TRUE(Address::isValid("313c94d73e16f8f9b8ff0cbc9a0c3f986ef7a25df26612d3ebc946713f09af15"));
}

TEST(InternetComputerAddress, Invalid) {
    // Invalid length: 63
    ASSERT_FALSE(Address::isValid("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4"));
    // Invalid length: 65
    ASSERT_FALSE(Address::isValid("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e1"));
    // Invalid checksum: changed the first character from 5 to 6.
    ASSERT_FALSE(Address::isValid("68b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e"));
    // Invalid characters
    ASSERT_FALSE(Address::isValid("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f*_"));
}

TEST(InternetComputerAddress, FromPrivateKey) {
    // TODO: Check public key type, finalize implementation

    auto privateKey = PrivateKey(parse_hex("__PRIVATE_KEY_DATA__"));
    auto address = Address(privateKey.getPublicKey(TWPublicKeyTypeED25519));
    ASSERT_EQ(address.string(), "__ADD_RESULTING_ADDRESS_HERE__");
}

TEST(InternetComputerAddress, FromPublicKey) {
    // TODO: Check public key type, finalize implementation

    auto publicKey = PublicKey(parse_hex("__PUBLIC_KEY_DATA__"), TWPublicKeyTypeED25519);
    auto address = Address(publicKey);
    ASSERT_EQ(address.string(), "__ADD_RESULTING_ADDRESS_HERE__");
}

TEST(InternetComputerAddress, FromString) {
    auto address = Address("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e");
    ASSERT_EQ(address.string(), "58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e");
}

} // namespace TW::InternetComputer::tests
