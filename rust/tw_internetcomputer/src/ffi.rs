// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use std::ffi::{c_char, CStr, CString};

use tw_memory::ffi::{
    c_byte_array::{CByteArray, CByteArrayResult},
    c_byte_array_ref::CByteArrayRef,
    c_result::ErrorCode,
};

use crate::{encode, validation};

#[repr(C)]
pub enum CEncodingCode {
    Ok = 0,
    InvalidPublicKey = 1,
    FailedDerEncode = 2,
    InvalidInput = 3,
}

impl From<encode::EncodePrincipalError> for CEncodingCode {
    fn from(error: encode::EncodePrincipalError) -> Self {
        match error {
            encode::EncodePrincipalError::InvalidPublicKey => CEncodingCode::InvalidPublicKey,
            encode::EncodePrincipalError::FailedDerEncode => CEncodingCode::FailedDerEncode,
        }
    }
}

impl From<CEncodingCode> for ErrorCode {
    fn from(error: CEncodingCode) -> Self {
        error as ErrorCode
    }
}

/// Determines if a provided string is a valid ICP address.
/// \param input *non-null* C-compatibile, nul-terminated string.
/// \return a boolean
#[no_mangle]
pub unsafe extern "C" fn tw_internetcomputer_is_address_valid(address: *const c_char) -> bool {
    let Ok(address) = CStr::from_ptr(address).to_str() else {
        return false;
    };

    if address.len() != 64 {
        return false;
    }

    validation::is_address_valid(address)
}

/// Encodes an expected secp256k1 extended public key to an Internet Computer principal.
/// \param pubkey *non-null* byte array.
/// \param pubkey_len the length of the `pubkey` byte array parameter.
/// \return C-compatible result with a C-compatible byte array.
#[no_mangle]
pub unsafe extern "C" fn tw_internetcomputer_encode_public_key_to_principal(
    pubkey: *const u8,
    pubkey_len: usize,
) -> CByteArrayResult {
    let Some(slice) = CByteArrayRef::new(pubkey, pubkey_len).as_slice() else {
        return CByteArrayResult::error(0);
    };

    encode::encode_public_key_to_principal(slice)
        .map(CByteArray::new)
        .map_err(CEncodingCode::from)
        .into()
}

/// Encodes a principal byte array to an Internet Computer address.
/// \param principal_bytes *non-null* byte array.
/// \param principal_len the length of the `principal_bytes` array.
/// \return *non-null* C-compatible, nul-terminated string.
#[no_mangle]
pub unsafe extern "C" fn tw_internetcomputer_principal_to_account_identifer(
    principal_bytes: *const u8,
    principal_len: usize,
) -> *mut c_char {
    let data = std::slice::from_raw_parts(principal_bytes, principal_len);
    let address = encode::principal_to_account_identifier(data);
    CString::new(address)
        .expect("failed to make c-string")
        .into_raw()
}

/// Encodes a principal byte array to an Internet Computer principal text.
/// \param principal_bytes *non-null* byte array.
/// \param principal_len the length of the `principal_bytes` array.
/// \return *non-null* C-compatible, nul-terminated string.
#[no_mangle]
pub unsafe extern "C" fn tw_encode_textual_principal(
    principal_bytes: *const u8,
    principal_len: usize,
) -> *mut c_char {
    let data = std::slice::from_raw_parts(principal_bytes, principal_len);
    let textual_principal = encode::encode_textual_principal(data);
    CString::new(textual_principal)
        .expect("failed to make c-string")
        .into_raw()
}
