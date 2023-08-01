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
    auto privateKey = PrivateKey(parse_hex("ee42eaada903e20ef6e5069f0428d552475c1ea7ed940842da6448f6ef9d48e7"));

    auto address = Address(privateKey.getPublicKey(TWPublicKeyTypeSECP256k1Extended));
    ASSERT_EQ(address.string(), "2f25874478d06cf68b9833524a6390d0ba69c566b02f46626979a3d6a4153211");
}

TEST(InternetComputerAddress, FromPublicKey) {
    const auto bytes2 = parse_hex("048542e6fb4b17d6dfcac3948fe412c00d626728815ee7cc70509603f1bc92128a6e7548f3432d6248bc49ff44a1e50f6389238468d17f7d7024de5be9b181dbc8");
    auto publicKey = PublicKey(bytes2, TWPublicKeyTypeSECP256k1Extended);
    auto address = Address(publicKey);
    ASSERT_EQ(address.string(), "2f25874478d06cf68b9833524a6390d0ba69c566b02f46626979a3d6a4153211");
}

TEST(InternetComputerAddress, FromString) {
    auto address = Address("58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e");
    ASSERT_EQ(address.string(), "58b26ace22a36a0011608a130e84c7cf34ba469c38d24ccf606152ce7de91f4e");
}

} // namespace TW::InternetComputer::tests
