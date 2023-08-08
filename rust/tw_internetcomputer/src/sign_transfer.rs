use candid::{
    Principal,
    Encode
};
use crate::types::account_identifier::Subaccount;
use ic_ledger_types::TransferArgs;
use ic_agent::{
    Agent,
    Identity,
    agent::UpdateBuilder,
    identity::{AnonymousIdentity, BasicIdentity, Secp256k1Identity},
};
use std::time::Duration;

pub fn sign(
    from_sub_account: Subaccount,
    to_principal: Principal,
    to_sub_account: Subaccount,
    amount: u64,
    fee: u64,
    memo: u64,
    created_at_time: u64
) -> Result<Vec<u8>, i32> {
    Result::Err(-1)
}


fn sign_implementation(
    canister_id: Principal,
    method_name: String,
    transfer_args: TransferArgs,
    key: String,
    ic_url: String,
    ingress_expiry: Duration /*Duration::from_secs(5 * 60)*/
) -> Result<Vec<u8>, String> {

    let args = Encode!(&transfer_args).map_err(|err| err.to_string())?;
    let identity = Secp256k1Identity::from_pem(key.as_bytes())
        .map(|identity| Box::new(identity))
        .map_err(|err| err.to_string())?;
    let agent = Agent::builder()
        .with_url(ic_url)
        .with_ingress_expiry(Some(ingress_expiry))
        .with_boxed_identity(identity)
        .build()
        .map_err(|err| err.to_string())?;
    let signature = UpdateBuilder::new(
        &agent,
        canister_id,
        method_name
    )
        .with_arg(args)
        .expire_after(ingress_expiry)
        .sign();

    Ok(vec![]) // Dummy Output
}