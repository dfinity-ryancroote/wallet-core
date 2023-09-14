// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package com.trustwallet.core.app.blockchains.chainkeybitcoin

import com.google.protobuf.ByteString
import com.trustwallet.core.app.utils.Numeric
import com.trustwallet.core.app.utils.toHex
import com.trustwallet.core.app.utils.toHexByteArray
import com.trustwallet.core.app.utils.toHexBytes
import com.trustwallet.core.app.utils.toHexBytesInByteString
import org.junit.Assert.assertEquals
import org.junit.Test
import wallet.core.java.AnySigner
import wallet.core.jni.CoinType
import wallet.core.jni.PrivateKey
import wallet.core.jni.proto.InternetComputer
import wallet.core.jni.proto.InternetComputer.SigningOutput

class TestChainkeyBitcoinSigner {

    init {
        System.loadLibrary("TrustWalletCore")
    }

    @Test
    fun ChainkeyBitcoinTransactionSigning() {
        val key = PrivateKey("227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be".toHexByteArray())

        val input = InternetComputer.SigningInput.newBuilder().setTransaction(InternetComputer.Transaction.newBuilder().apply {
            icrc1Transfer = InternetComputer.Transaction.Icrc1Transfer.newBuilder().apply {
                toIcrcAccount = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1"
                amount = 100000000
                memo = ByteString.fromHex("a0")
                createdAtTimeNanos = 1691709940000000000
            }.build()
        }.build()).setPrivateKey(ByteString.copyFrom(key.data()))
        val output = AnySigner.sign(input.build(), CoinType.CHAINKEYBITCOIN, SigningOutput.parser())
        assertEquals(output.signedTransaction.toByteArray().toHex(), "0x81826b5452414e53414354494f4e81a266757064617465a367636f6e74656e74a66c726571756573745f747970656463616c6c6e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d026b63616e69737465725f69644a000000000230000601016b6d6574686f645f6e616d656e69637263315f7472616e736665726361726758934449444c066c06fbca0101c6fcb60204ba89e5c20402a2de94eb060282f3f3910c05d8a38ca80d7d6c02b3b0dac30368ad86ca8305026e036d7b6e7d6e780100011db56bf994b37ae8e79f5ce000be1727a6060ae4eef24736b7cc999c3c0201200000000000000000000000000000000000000000000000000000000000000001000101a000010088b2343a297a1780c2d72f6d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018f4187d18bc18d818aa1883182618aa182c184f18a8185a18b50511187b18eb18fb185f0c18741218331836183a18dd18cf189b18ed18f418220e184d1842189b1898121857185d188718c418df18c3188b18b418c0185818201843182f18f4182e185a18f618bf16182a1845183c18fd184e0618fe18586a726561645f7374617465a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d0265706174687381824e726571756573745f73746174757358204dfea0adbdda4c3b5145e162a91811930db13d8949fe36acb9759a934df147a96d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018cb1851186a18e7186518d3188e1846185a0b1838185a18bd182918cd187b18a418a718e618a018b6183a18c118cd18de18ae185004189f18cd189618dc183e18da1821011820188b181a18f9189c189318741881185b18fa18e9187a18dc18db1518e10d18d1187118ef18360d182418fb181c1889185c188a")
    }

    @Test
    fun ChainkeyBitcoinTransactionInvalidIcrcAccount() {
        val key = PrivateKey("227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be".toHexByteArray())

        val input = InternetComputer.SigningInput.newBuilder().setTransaction(InternetComputer.Transaction.newBuilder().apply {
            icrc1Transfer = InternetComputer.Transaction.Icrc1Transfer.newBuilder().apply {
                toIcrcAccount = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i."
                amount = 100000000
                memo = ByteString.fromHex("a0")
                createdAtTimeNanos = 1691709940000000000
            }.build()
        }.build()).setPrivateKey(ByteString.copyFrom(key.data()))
        val output = AnySigner.sign(input.build(), CoinType.INTERNETCOMPUTER, SigningOutput.parser())
        assertEquals(output.error.number, 16)
    }

    @Test
    fun ChainkeyBitcoinTransactionInvalidAmount() {
        val key = PrivateKey("227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be".toHexByteArray())

        val input = InternetComputer.SigningInput.newBuilder().setTransaction(InternetComputer.Transaction.newBuilder().apply {
            icrc1Transfer = InternetComputer.Transaction.Icrc1Transfer.newBuilder().apply {
                toIcrcAccount = "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1"
                amount = 0
                memo = ByteString.fromHex("a0")
                createdAtTimeNanos = 1691709940000000000
            }.build()
        }.build()).setPrivateKey(ByteString.copyFrom(key.data()))
        val output = AnySigner.sign(input.build(), CoinType.INTERNETCOMPUTER, SigningOutput.parser())
        assertEquals(output.error.number, 23)
    }
}
