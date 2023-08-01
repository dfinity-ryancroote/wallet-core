use std::str::FromStr;

use crate::types::account_identifier::AccountIdentifier;

pub fn is_address_valid(address: &str) -> bool {
    AccountIdentifier::from_str(address).is_ok()
}
