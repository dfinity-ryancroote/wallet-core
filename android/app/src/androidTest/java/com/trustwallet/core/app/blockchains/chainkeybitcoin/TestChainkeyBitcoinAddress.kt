// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package com.trustwallet.core.app.blockchains.chainkeybitcoin

import com.trustwallet.core.app.utils.toHex
import com.trustwallet.core.app.utils.toHexByteArray
import org.junit.Assert.assertEquals
import org.junit.Test
import wallet.core.jni.*

class TestChainkeyBitcoinAddress {

    init {
        System.loadLibrary("TrustWalletCore")
    }

    @Test
    fun testAddress() {
        // TODO: Check and finalize implementation

        val key = PrivateKey("ee42eaada903e20ef6e5069f0428d552475c1ea7ed940842da6448f6ef9d48e7".toHexByteArray())
        val pubkey = key.publicKeyEd25519
        val address = AnyAddress(pubkey, CoinType.CHAINKEYBITCOIN)
        val expected = AnyAddress("iqlzk-yhdp6-7cb7b-zjtsb-anxbf-lv4uo-53aqu-r7xzl-cjizi-phwm4-3qe", CoinType.CHAINKEYBITCOIN)

        assertEquals(pubkey.data().toHex(), "0x048542e6fb4b17d6dfcac3948fe412c00d626728815ee7cc70509603f1bc92128a6e7548f3432d6248bc49ff44a1e50f6389238468d17f7d7024de5be9b181dbc8")
        assertEquals(address.description(), expected.description())
    }
}
