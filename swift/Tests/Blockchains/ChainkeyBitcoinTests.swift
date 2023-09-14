// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import WalletCore
import XCTest

class ChainkeyBitcoinTests: XCTestCase {
    // TODO: Check and finalize implementation

    func testAddress() {
        let key = PrivateKey(data: Data(hexString: "ee42eaada903e20ef6e5069f0428d552475c1ea7ed940842da6448f6ef9d48e7")!)!
        let pubkey = key.getPublicKeySecp256k1(compressed: false)
        let address = AnyAddress(publicKey: pubkey, coin: .chainkeyBitcoin)
        let addressFromString = AnyAddress(string: "iqlzk-yhdp6-7cb7b-zjtsb-anxbf-lv4uo-53aqu-r7xzl-cjizi-phwm4-3qe", coin: .chainkeyBitcoin)!

        XCTAssertEqual(pubkey.data.hexString, "048542e6fb4b17d6dfcac3948fe412c00d626728815ee7cc70509603f1bc92128a6e7548f3432d6248bc49ff44a1e50f6389238468d17f7d7024de5be9b181dbc8")
        XCTAssertEqual(address.description, addressFromString.description)
    }

    func testSign() {
        // TODO: Create implementation
    }
}
