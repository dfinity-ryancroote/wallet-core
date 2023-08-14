// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include "Data.h"
#include "rust/Wrapper.h"
#include "rust/bindgen/WalletCoreRSBindgen.h"
#include "../PrivateKey.h"
#include "../proto/InternetComputer.pb.h"

namespace TW::InternetComputer {

/// Helper class that performs InternetComputer transaction signing.
class Signer {
public:
    /// Hide default constructor
    Signer() = delete;

    /// Signs a Proto::SigningInput transaction
    static Proto::SigningOutput sign(const Proto::SigningInput& input) noexcept;
    static Proto::SigningOutput signTransfer(const Data privateKey, const Proto::Transaction_Transfer& transfer) noexcept;
};

} // namespace TW::InternetComputer
