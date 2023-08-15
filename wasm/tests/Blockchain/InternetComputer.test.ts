// Copyright © 2017-2022 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

import "mocha";
import { assert } from "chai";
import { Buffer } from "buffer";
import { TW } from "../../dist";

describe("InternetComputer", () => {

    it("test address", () => {
        const { PrivateKey, HexCoding, AnyAddress, CoinType, Curve } = globalThis.core;
        const privateKeyBytes = HexCoding.decode("ee42eaada903e20ef6e5069f0428d552475c1ea7ed940842da6448f6ef9d48e7");

        assert.isTrue(PrivateKey.isValid(privateKeyBytes, Curve.secp256k1));

        const privateKey = PrivateKey.createWithData(privateKeyBytes);
        const publicKey = privateKey.getPublicKeySecp256k1(false);

        const address = AnyAddress.createWithPublicKey(publicKey, CoinType.InternetComputer);

        assert.equal(address.description(), "2f25874478d06cf68b9833524a6390d0ba69c566b02f46626979a3d6a4153211");

        privateKey.delete();
        publicKey.delete();
        address.delete();
    });

    it("test sign", () => { });

});