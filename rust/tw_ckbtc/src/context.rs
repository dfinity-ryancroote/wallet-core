use tw_internet_computer::{
    context::{CanisterId, InternetComputerContext},
    icrc::address::IcrcAccount,
    protocol::principal::Principal,
};

pub struct CkBtcCanister;

impl CanisterId for CkBtcCanister {
    fn principal_id() -> Principal {
        // ckBTC canister ID: mxzaz-hqaaa-aaaar-qaada-cai
        Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x00, 0x06, 0x01, 0x01])
    }
}

pub struct CkBtcContext;

impl InternetComputerContext for CkBtcContext {
    type Address = IcrcAccount;
    type Canister = CkBtcCanister;
}

#[cfg(test)]
mod test {}
