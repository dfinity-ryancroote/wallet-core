// Copyright © 2017-2023 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

use std::ffi::{c_char, CStr, CString};

use ic_ledger_types::{Subaccount, DEFAULT_SUBACCOUNT};
use tw_memory::ffi::{
    c_byte_array::{CByteArray, CByteArrayResult},
    c_byte_array_ref::CByteArrayRef,
    c_result::ErrorCode,
};

use crate::{encode, validation};
use candid::Principal;

const SUB_ACCOUNT_SIZE_BYTES: usize = 32;
const MAX_PRINCIPAL_SIZE_BYTES: usize = 29;

// Error Codes
const SIGN_ERROR_INVALID_TO_SUB_ACCOUNT: i32 = 1001;
const SIGN_ERROR_INVALID_FROM_PRINCIPAL: i32 = 1002;
const SIGN_ERROR_INVALID_FROM_SUB_ACCOUNT: i32 = 1003;

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

/// Encodes a principal byte array to an Internet Computer principal text.
/// TODO
/// TODO
/// \return TODO
#[no_mangle]
pub unsafe extern "C" fn tw_sign(
    from_sub_account_bytes: *const u8,
    to_principal: *const c_char,
    to_sub_account_bytes: *const u8,
    amount: u64,
    fee: u64,
    memo: u64,
    created_at_time: u64,
) -> CByteArrayResult {
    let from_sub_account =
        match CByteArrayRef::new(from_sub_account_bytes, SUB_ACCOUNT_SIZE_BYTES).as_slice() {
            Some(slice) => match slice.try_into() {
                Ok(value) => Subaccount(value),
                Err(_) => return CByteArrayResult::error(SIGN_ERROR_INVALID_TO_SUB_ACCOUNT),
            },
            None => return CByteArrayResult::error(SIGN_ERROR_INVALID_TO_SUB_ACCOUNT),
        };

    let to_principal = match CStr::from_ptr(to_principal).to_str() {
        Ok(principal_text) => match Principal::from_text(principal_text) {
            Ok(principal) => principal,
            Err(_) => return CByteArrayResult::error(SIGN_ERROR_INVALID_FROM_PRINCIPAL),
        },
        Err(_) => return CByteArrayResult::error(SIGN_ERROR_INVALID_FROM_PRINCIPAL),
    };

    let to_sub_account =
        match CByteArrayRef::new(to_sub_account_bytes, SUB_ACCOUNT_SIZE_BYTES).as_slice() {
            Some(slice) => match slice.try_into() {
                Ok(value) => Subaccount(value),
                Err(_) => return CByteArrayResult::error(SIGN_ERROR_INVALID_TO_SUB_ACCOUNT),
            },
            None => DEFAULT_SUBACCOUNT,
        };

    CByteArrayResult::ok(CByteArray::new(vec![]))
}
