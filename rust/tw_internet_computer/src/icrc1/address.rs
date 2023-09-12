use candid::{types::principal::PrincipalError, CandidType};
use serde::{Deserialize, Serialize};
use tw_encoding::{base32, hex};
use tw_hash::crc32::crc32;

use crate::protocol::principal::Principal;

pub type Subaccount = [u8; 32];

pub const DEFAULT_SUBACCOUNT: &Subaccount = &[0; 32];

// Account representation of ledgers supporting the ICRC1 standard
#[derive(Serialize, CandidType, Deserialize, Clone, Debug, Copy)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Subaccount>,
}

impl Account {
    #[inline]
    pub fn effective_subaccount(&self) -> &Subaccount {
        self.subaccount.as_ref().unwrap_or(DEFAULT_SUBACCOUNT)
    }
}

impl PartialEq for Account {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.effective_subaccount() == other.effective_subaccount()
    }
}

impl Eq for Account {}

impl std::cmp::PartialOrd for Account {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Account {
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

impl std::fmt::Display for Account {
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

impl From<Principal> for Account {
    fn from(owner: Principal) -> Self {
        Self {
            owner,
            subaccount: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ICRC1TextReprError {
    DefaultSubaccountShouldBeOmitted,
    InvalidChecksum { expected: String },
    InvalidPrincipal(PrincipalError),
    InvalidSubaccount(String),
    LeadingZeroesInSubaccount,
    MissingChecksum,
}

impl std::fmt::Display for ICRC1TextReprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ICRC1TextReprError::DefaultSubaccountShouldBeOmitted => {
                write!(f, "default subaccount should be omitted")
            },
            ICRC1TextReprError::InvalidChecksum { expected } => {
                write!(f, "invalid checksum (expected: {})", expected)
            },
            ICRC1TextReprError::InvalidPrincipal(e) => write!(f, "invalid principal: {}", e),
            ICRC1TextReprError::InvalidSubaccount(e) => write!(f, "invalid subaccount: {}", e),
            ICRC1TextReprError::LeadingZeroesInSubaccount => {
                write!(f, "subaccount should not have leading zeroes")
            },
            ICRC1TextReprError::MissingChecksum => write!(f, "missing checksum"),
        }
    }
}

impl std::error::Error for ICRC1TextReprError {}

impl std::str::FromStr for Account {
    type Err = ICRC1TextReprError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('.') {
            Some((principal_checksum, subaccount)) => {
                let (principal, checksum) = match principal_checksum.rsplit_once('-') {
                    // The checksum is 7 characters (crc32 encoded via base32) while principal
                    // groups are 5 characters
                    Some((_, checksum)) if checksum.len() != 7 => {
                        return Err(Self::Err::MissingChecksum)
                    },
                    Some(principal_and_checksum) => principal_and_checksum,
                    None => return Err(Self::Err::MissingChecksum),
                };
                if subaccount.starts_with('0') {
                    return Err(Self::Err::LeadingZeroesInSubaccount);
                }
                let owner = Principal::from_text(principal).map_err(Self::Err::InvalidPrincipal)?;
                let subaccount = hex::decode(&format!("{:0>64}", subaccount)).map_err(|e| {
                    Self::Err::InvalidSubaccount(format!("subaccount is not hex-encoded: {e}"))
                })?;
                let subaccount: Subaccount = subaccount.try_into().map_err(|_| {
                    Self::Err::InvalidSubaccount("subaccount is longer than 32 bytes".to_string())
                })?;
                if &subaccount == DEFAULT_SUBACCOUNT {
                    return Err(Self::Err::DefaultSubaccountShouldBeOmitted);
                }
                let expected_checksum =
                    full_account_checksum(owner.as_slice(), subaccount.as_slice());
                if checksum != expected_checksum {
                    return Err(Self::Err::InvalidChecksum {
                        expected: expected_checksum,
                    });
                }
                Ok(Self {
                    owner,
                    subaccount: Some(subaccount),
                })
            },
            None => Principal::from_text(s)
                .map_err(Self::Err::InvalidPrincipal)
                .map(Account::from),
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
        let account = Account {
            owner: principal.clone(),
            subaccount: None,
        };

        assert_eq!(
            "iooej-vlrze-c5tme-tn7qt-vqe7z-7bsj5-ebxlc-hlzgs-lueo3-3yast-pae",
            account.to_string()
        );

        let account = Account {
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
        let account = Account {
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

        let account = Account {
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
