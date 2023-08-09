// DISCLAIMER:
// Do not modify this file arbitrarily.
// The contents are borrowed from:
// dfinity-lab/dfinity@25999dd54d29c24edb31483801bddfd8c1d780c8
// https://github.com/dfinity-lab/dfinity/blob/master/rs/rosetta-api/canister/src/account_identifier.rs
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use tw_encoding::hex;
use tw_hash::sha2::sha224;

const SUB_ACCOUNT_ZERO: Subaccount = Subaccount([0; 32]);
const ACCOUNT_DOMAIN_SEPERATOR: &[u8] = b"\x0Aaccount-id";

/// While this is backed by an array of length 28, it's canonical representation
/// is a hex string of length 64. The first 8 characters are the CRC-32 encoded
/// hash of the following 56 characters of hex. Both, upper and lower case
/// characters are valid in the input string and can even be mixed.
///
/// When it is encoded or decoded it will always be as a string to make it
/// easier to use from DFX.
#[derive(
    Clone, Copy, Hash, Debug, CandidType, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct AccountIdentifier {
    pub hash: [u8; 28],
}

impl AccountIdentifier {
    pub fn new(account: Principal) -> AccountIdentifier {
        let mut input = vec![];
        input.extend_from_slice(ACCOUNT_DOMAIN_SEPERATOR);
        input.extend_from_slice(account.as_slice());
        input.extend_from_slice(&SUB_ACCOUNT_ZERO.0[..]);

        let output = sha224(&input);
        let mut hash: [u8; 28] = [0; 28];
        hash.copy_from_slice(&output);

        AccountIdentifier { hash }
    }

    pub fn from_hex(hex_str: &str) -> Result<AccountIdentifier, String> {
        let hex: Vec<u8> = hex::decode(hex_str).map_err(|e| e.to_string())?;
        Self::from_slice(&hex[..])
    }

    /// Goes from the canonical format (with checksum) encoded in bytes rather
    /// than hex to AccountIdentifier
    pub fn from_slice(v: &[u8]) -> Result<AccountIdentifier, String> {
        // Trim this down when we reach rust 1.48
        let hex: Box<[u8; 32]> = match v.to_vec().into_boxed_slice().try_into() {
            Ok(h) => h,
            Err(_) => {
                let hex_str = hex::encode(v, false);
                return Err(format!(
                    "{} has a length of {} but we expected a length of 64",
                    hex_str,
                    hex_str.len()
                ));
            },
        };
        check_sum(*hex)
    }

    /// Converts this account identifier into a binary "address".
    /// The address is CRC32(identifier) . identifier.
    pub fn to_address(self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..4].copy_from_slice(&self.generate_checksum());
        result[4..32].copy_from_slice(&self.hash);
        result
    }

    pub fn to_hex(self) -> String {
        hex::encode(&self.to_vec(), false)
    }

    pub fn to_vec(self) -> Vec<u8> {
        [&self.generate_checksum()[..], &self.hash[..]].concat()
    }

    pub fn generate_checksum(&self) -> [u8; 4] {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.hash);
        hasher.finalize().to_be_bytes()
    }
}

impl Display for AccountIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.to_hex().fmt(f)
    }
}

impl FromStr for AccountIdentifier {
    type Err = String;

    fn from_str(s: &str) -> Result<AccountIdentifier, String> {
        AccountIdentifier::from_hex(s)
    }
}

fn check_sum(hex: [u8; 32]) -> Result<AccountIdentifier, String> {
    // Get the checksum provided
    let found_checksum = &hex[0..4];

    // Copy the hash into a new array
    let mut hash = [0; 28];
    hash.copy_from_slice(&hex[4..32]);

    let account_id = AccountIdentifier { hash };
    let expected_checksum = account_id.generate_checksum();

    // Check the generated checksum matches
    if expected_checksum == found_checksum {
        Ok(account_id)
    } else {
        Err(format!(
            "Checksum failed for {}, expected check bytes {} but found {}",
            hex::encode(&hex[..], false),
            hex::encode(&expected_checksum, false),
            hex::encode(found_checksum, false),
        ))
    }
}

/// Subaccounts are arbitrary 32-byte values.
#[derive(Clone, Hash, Debug, PartialEq, Eq, Copy)]
pub struct Subaccount(pub [u8; 32]);
