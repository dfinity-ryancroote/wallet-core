// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import WalletCore
import XCTest

class InternetComputerTests: XCTestCase {
    // TODO: Check and finalize implementation

    func testAddress() {
        let key = PrivateKey(data: Data(hexString: "ee42eaada903e20ef6e5069f0428d552475c1ea7ed940842da6448f6ef9d48e7")!)!
        let pubkey = key.getPublicKeySecp256k1(compressed: false)
        let address = AnyAddress(publicKey: pubkey, coin: .internetComputer)
        let addressFromString = AnyAddress(string: "2f25874478d06cf68b9833524a6390d0ba69c566b02f46626979a3d6a4153211", coin: .internetComputer)!

        XCTAssertEqual(pubkey.data.hexString, "048542e6fb4b17d6dfcac3948fe412c00d626728815ee7cc70509603f1bc92128a6e7548f3432d6248bc49ff44a1e50f6389238468d17f7d7024de5be9b181dbc8")
        XCTAssertEqual(address.description, addressFromString.description)
    }

    func testSign() {
        let key = PrivateKey(data: Data(hexString: "227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be")!)!
        let input = InternetComputerSigningInput.with {
            $0.privateKey = key.data
            $0.transaction = InternetComputerTransaction.with {
                $0.transfer = InternetComputerTransaction.Transfer.with {
                    $0.toAccountIdentifier = "943d12e762f43806782f524b8f90297298a6d79e4749b41b585ec427409c826a"
                    $0.amount = 100000000
                    $0.memo = 0
                    $0.currentTimestampSecs = 1691709940
                }
            }
                
        }
        let output: InternetComputerSigningOutput = AnySigner.sign(input: input, coin: .internetComputer)
        XCTAssertEqual(output.signedTransaction.hexString, "81826b5452414e53414354494f4e81a266757064617465a367636f6e74656e74a66c726571756573745f747970656463616c6c6e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d026b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d656773656e645f70626361726758400a0012070a050880c2d72f1a0308904e2a220a20943d12e762f43806782f524b8f90297298a6d79e4749b41b585ec427409c826a3a0a088090caa5a3a78abd176d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018d8189d18ee188a1118a81858184018da188d188c18b800184c18f611182718ea18931899186f183318c518711848186718841718351825181e187c18710018a21871183618f6184b18cd18e618e418ea182c18d118c91857188d140c18b4182a188018c51871189f1418b518cf182e18b618a418fd18a36a726561645f7374617465a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b177a297215cfe8006673656e646572581d971cd2ddeecd1cf1b28be914d7a5c43441f6296f1f9966a7c8aff68d0265706174687381824e726571756573745f7374617475735820b20f43257a5e87542693561e20a6076d515395e49623fcecd6c5b5640b8db8c36d73656e6465725f7075626b65799858183018561830100607182a1886184818ce183d02010605182b188104000a0318420004183d18ab183a182118a81838184d184c187e1852188a187e18dc18d8184418ea18cd18c5189518ac188518b518bc181d188515186318bc18e618ab18d2184318d3187c184f18cd18f018de189b18b5181918dd18ef1889187218e71518c40418d4189718881843187218c611182e18cc18e6186b182118630218356a73656e6465725f736967984018a8189b12186d18a4188d18fb18f71869187918f70e1825181d185a0318440b18e0186e1820183f1834188016186818dd183b18d518de18941849187e1882186e18591861187218ac0a18de18df1858183718b6182818930c18431864183718f60a18ef1824185e18ed184e18841839185718d5091888")
    }
    
    func testSignWithInvalidToAccountIdentifier() {
        let key = PrivateKey(data: Data(hexString: "227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be")!)!
        let input = InternetComputerSigningInput.with {
            $0.privateKey = key.data
            $0.transaction = InternetComputerTransaction.with {
                $0.transfer = InternetComputerTransaction.Transfer.with {
                    $0.toAccountIdentifier = "643d12e762f43806782f524b8f90297298a6d79e4749b41b585ec427409c826b"
                    $0.amount = 100000000
                    $0.memo = 0
                    $0.currentTimestampSecs = 1691709940
                }
            }
                
        }
        let output: InternetComputerSigningOutput = AnySigner.sign(input: input, coin: .internetComputer)
        XCTAssertEqual(output.error.rawValue, 16)
    }
    
    func testSignWithInvalidAmount() {
        let key = PrivateKey(data: Data(hexString: "227102911bb99ce7285a55f952800912b7d22ebeeeee59d77fc33a5d7c7080be")!)!
        let input = InternetComputerSigningInput.with {
            $0.privateKey = key.data
            $0.transaction = InternetComputerTransaction.with {
                $0.transfer = InternetComputerTransaction.Transfer.with {
                    $0.toAccountIdentifier = "943d12e762f43806782f524b8f90297298a6d79e4749b41b585ec427409c826a"
                    $0.amount = 0
                    $0.memo = 0
                    $0.currentTimestampSecs = 1691709940
                }
            }
                
        }
        let output: InternetComputerSigningOutput = AnySigner.sign(input: input, coin: .internetComputer)
        XCTAssertEqual(output.error.rawValue, 23)
    }
}
