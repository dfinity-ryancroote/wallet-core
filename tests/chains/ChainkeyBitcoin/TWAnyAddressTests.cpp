// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "HexCoding.h"
#include <TrustWalletCore/TWAnyAddress.h>

#include "TestUtilities.h"
#include <gtest/gtest.h>

using namespace TW;

TEST(TWChainkeyBitcoin, Address) {
    auto string = STRING("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae");
    auto addr = WRAP(TWAnyAddress, TWAnyAddressCreateWithString(string.get(), TWCoinTypeChainkeyBitcoin));
    auto string2 = WRAPS(TWAnyAddressDescription(addr.get()));
    EXPECT_TRUE(TWStringEqual(string.get(), string2.get()));

    auto string_with_subaccount = STRING("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    auto addr2 = WRAP(TWAnyAddress, TWAnyAddressCreateWithString(string_with_subaccount.get(), TWCoinTypeChainkeyBitcoin));
    auto string_with_subaccount2 = WRAPS(TWAnyAddressDescription(addr2.get()));
    EXPECT_TRUE(TWStringEqual(string_with_subaccount.get(), string_with_subaccount2.get()));

    auto string_with_short_subaccount = STRING("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1");
    auto addr3 = WRAP(TWAnyAddress, TWAnyAddressCreateWithString(string_with_short_subaccount.get(), TWCoinTypeChainkeyBitcoin));
    auto string_with_short_subaccount2 = WRAPS(TWAnyAddressDescription(addr3.get()));
    EXPECT_TRUE(TWStringEqual(string_with_short_subaccount.get(), string_with_short_subaccount2.get()));
}
