use candid::CandidType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tw_coin_entry::{
    coin_entry::CoinAddress,
    error::{AddressError, AddressResult},
};
use tw_encoding::{base32, hex};
use tw_hash::crc32::crc32;
use tw_keypair::ecdsa::secp256k1::PublicKey;

use crate::{address::Address, protocol::principal::Principal};

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

pub trait IcrcAddress: std::str::FromStr<Err = AddressError> + Into<IcrcAccount> {
    fn from_str_optional(s: &str) -> AddressResult<Option<Self>> {
        if s.is_empty() {
            return Ok(None);
        }

        Self::from_str(s).map(Some)
    }
}

// Account representation of ledgers supporting the ICRC1 standard
#[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy)]
pub struct IcrcAccount {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

impl IcrcAccount {
    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(DEFAULT_SUBACCOUNT)
    }
}

impl Address for IcrcAccount {
    fn from_str_optional(s: &str) -> AddressResult<Option<Self>> {
        if s.is_empty() {
            return Ok(None);
        }

        Self::from_str(s).map(Some)
    }
}

impl PartialEq for IcrcAccount {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for IcrcAccount {}

impl std::cmp::PartialOrd for IcrcAccount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for IcrcAccount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.owner.cmp(&other.owner).then_with(|| {
            self.effective_subaccount()
                .cmp(other.effective_subaccount())
        })
    }
}

fn full_account_checksum(owner: &[u8], subaccount: &[u8]) -> String {
    let mut input = vec![];
    input.extend_from_slice(owner);
    input.extend_from_slice(subaccount);

    let checksum = crc32(&input).to_be_bytes();
    base32::encode(&checksum, None, false)
        .unwrap()
        .to_lowercase()
}

impl std::fmt::Display for IcrcAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/TextualEncoding.md#textual-encoding-of-icrc-1-accounts
        match &self.subaccount {
            None => write!(f, "{}", self.owner.to_text()),
            Some(subaccount) if subaccount == &[0; 32] => write!(f, "{}", self.owner.to_text()),
            Some(subaccount) => {
                let checksum = full_account_checksum(self.owner.as_slice(), subaccount.as_slice());
                let hex_subaccount = hex::encode(subaccount.as_slice(), false);
                let hex_subaccount = hex_subaccount.trim_start_matches('0');
                write!(
                    f,
                    "{}-{}.{}",
                    self.owner.to_text(),
                    checksum,
                    hex_subaccount
                )
            },
        }
    }
}

impl From<Principal> for IcrcAccount {
    fn from(owner: Principal) -> Self {
        Self {
            owner,
            subaccount: None,
        }
    }
}

impl From<&PublicKey> for IcrcAccount {
    fn from(public_key: &PublicKey) -> Self {
        let principal = Principal::from(public_key);
        IcrcAccount::from(principal)
    }
}

impl CoinAddress for IcrcAccount {
    fn data(&self) -> tw_memory::Data {
        let mut data = vec![];
        data.extend_from_slice(self.owner.as_slice());
        data.extend_from_slice(&self.subaccount.unwrap_or_default());
        data
    }
}

impl std::str::FromStr for IcrcAccount {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('.') {
            Some((principal_checksum, subaccount)) => {
                let (principal, checksum) = match principal_checksum.rsplit_once('-') {
                    // The checksum is 7 characters (crc32 encoded via base32) while principal
                    // groups are 5 characters
                    Some((_, checksum)) if checksum.len() != 7 => {
                        return Err(Self::Err::InvalidChecksum)
                    },
                    Some(principal_and_checksum) => principal_and_checksum,
                    None => return Err(Self::Err::InvalidChecksum),
                };
                if subaccount.starts_with('0') {
                    return Err(Self::Err::FromHexError);
                }
                let owner = Principal::from_text(principal).map_err(|_| Self::Err::FromHexError)?;
                let subaccount = hex::decode(&format!("{:0>64}", subaccount))
                    .map_err(|_| Self::Err::FromHexError)?;
                let subaccount: Subaccount =
                    subaccount.try_into().map_err(|_| Self::Err::FromHexError)?;
                if &subaccount == DEFAULT_SUBACCOUNT {
                    return Err(Self::Err::FromHexError);
                }
                let expected_checksum =
                    full_account_checksum(owner.as_slice(), subaccount.as_slice());
                if checksum != expected_checksum {
                    return Err(AddressError::InvalidChecksum);
                }
                Ok(Self {
                    owner,
                    subaccount: Some(subaccount),
                })
            },
            None => Principal::from_text(s)
                .map_err(|_| Self::Err::FromHexError)
                .map(IcrcAccount::from),
        }
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_string() {
        let principal =
            Principal::from_text("iooej-vlrze-c5tme-tn7qt-vqe7z-7bsj5-ebxlc-hlzgs-lueo3-3yast-pae")
                .unwrap();
        let account = IcrcAccount {
            owner: principal.clone(),
            subaccount: None,
        };

        assert_eq!(
            "iooej-vlrze-c5tme-tn7qt-vqe7z-7bsj5-ebxlc-hlzgs-lueo3-3yast-pae",
            account.to_string()
        );

        let account = IcrcAccount {
            owner: principal,
            subaccount: Some([0; 32]),
        };
        assert_eq!(
            "iooej-vlrze-c5tme-tn7qt-vqe7z-7bsj5-ebxlc-hlzgs-lueo3-3yast-pae",
            account.to_string()
        );

        let principal =
            Principal::from_text("k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae")
                .unwrap();
        let account = IcrcAccount {
            owner: principal.clone(),
            subaccount: Some([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ]),
        };

        assert_eq!(
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-dfxgiyy.102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            account.to_string()
        );

        let account = IcrcAccount {
            owner: principal,
            subaccount: Some([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ]),
        };
        assert_eq!(
            "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae-6cc627i.1",
            account.to_string()
        );
    }
}
