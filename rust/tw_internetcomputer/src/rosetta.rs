use ic_agent::agent::EnvelopeContent;
use ic_agent::export::Principal;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

pub const STATUS_COMPLETED: &str = "COMPLETED";
pub const TRANSACTION: &str = "TRANSACTION";
pub const MINT: &str = "MINT";
pub const BURN: &str = "BURN";
pub const FEE: &str = "FEE";
pub const STAKE: &str = "STAKE";
pub const START_DISSOLVE: &str = "START_DISSOLVE";
pub const STOP_DISSOLVE: &str = "STOP_DISSOLVE";
pub const SET_DISSOLVE_TIMESTAMP: &str = "SET_DISSOLVE_TIMESTAMP";
pub const CHANGE_AUTO_STAKE_MATURITY: &str = "CHANGE_AUTO_STAKE_MATURITY";
pub const DISBURSE: &str = "DISBURSE";
pub const DISSOLVE_TIME_UTC_SECONDS: &str = "dissolve_time_utc_seconds";
pub const ADD_HOT_KEY: &str = "ADD_HOT_KEY";
pub const REMOVE_HOTKEY: &str = "REMOVE_HOTKEY";
pub const SPAWN: &str = "SPAWN";
pub const MERGE_MATURITY: &str = "MERGE_MATURITY";
pub const REGISTER_VOTE: &str = "REGISTER_VOTE";
pub const STAKE_MATURITY: &str = "STAKE_MATURITY";
pub const NEURON_INFO: &str = "NEURON_INFO";
pub const FOLLOW: &str = "FOLLOW";

/// `RequestType` contains all supported values of `Operation.type`.
/// Extra information, such as `neuron_index` should only be included
/// if it cannot be parsed from the submit payload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum RequestType {
    // Aliases for backwards compatibility
    #[serde(rename = "TRANSACTION")]
    #[serde(alias = "Send")]
    Send,
    #[serde(rename = "STAKE")]
    #[serde(alias = "Stake")]
    Stake { neuron_index: u64 },
    #[serde(rename = "SET_DISSOLVE_TIMESTAMP")]
    #[serde(alias = "SetDissolveTimestamp")]
    SetDissolveTimestamp { neuron_index: u64 },
    #[serde(rename = "CHANGE_AUTO_STAKE_MATURITY")]
    #[serde(alias = "ChangeAutoStakeMaturity")]
    ChangeAutoStakeMaturity { neuron_index: u64 },
    #[serde(rename = "START_DISSOLVE")]
    #[serde(alias = "StartDissolve")]
    StartDissolve { neuron_index: u64 },
    #[serde(rename = "STOP_DISSOLVE")]
    #[serde(alias = "StopDissolve")]
    StopDissolve { neuron_index: u64 },
    #[serde(rename = "DISBURSE")]
    #[serde(alias = "Disperse")]
    Disburse { neuron_index: u64 },
    #[serde(rename = "ADD_HOT_KEY")]
    #[serde(alias = "AddHotKey")]
    AddHotKey { neuron_index: u64 },
    #[serde(rename = "REMOVE_HOTKEY")]
    #[serde(alias = "RemoveHotKey")]
    RemoveHotKey { neuron_index: u64 },
    #[serde(rename = "SPAWN")]
    #[serde(alias = "Spawn")]
    Spawn { neuron_index: u64 },
    #[serde(rename = "MERGE_MATURITY")]
    #[serde(alias = "MergeMaturity")]
    MergeMaturity { neuron_index: u64 },
    #[serde(rename = "STAKE_MATURITY")]
    #[serde(alias = "StakeMaturity")]
    StakeMaturity { neuron_index: u64 },
    #[serde(rename = "REGISTER_VOTE")]
    #[serde(alias = "RegisterVote")]
    RegisterVote { neuron_index: u64 },
    #[serde(rename = "NEURON_INFO")]
    #[serde(alias = "NeuronInfo")]
    NeuronInfo {
        neuron_index: u64,
        controller: Option<Principal>,
    },
    #[serde(rename = "FOLLOW")]
    #[serde(alias = "Follow")]
    Follow {
        neuron_index: u64,
        controller: Option<Principal>,
    },
}

impl RequestType {
    pub fn into_str(self) -> &'static str {
        match self {
            RequestType::Send { .. } => TRANSACTION,
            RequestType::Stake { .. } => STAKE,
            RequestType::SetDissolveTimestamp { .. } => SET_DISSOLVE_TIMESTAMP,
            RequestType::ChangeAutoStakeMaturity { .. } => CHANGE_AUTO_STAKE_MATURITY,
            RequestType::StartDissolve { .. } => START_DISSOLVE,
            RequestType::StopDissolve { .. } => STOP_DISSOLVE,
            RequestType::Disburse { .. } => DISBURSE,
            RequestType::AddHotKey { .. } => ADD_HOT_KEY,
            RequestType::RemoveHotKey { .. } => REMOVE_HOTKEY,
            RequestType::Spawn { .. } => SPAWN,
            RequestType::MergeMaturity { .. } => MERGE_MATURITY,
            RequestType::RegisterVote { .. } => REGISTER_VOTE,
            RequestType::StakeMaturity { .. } => STAKE_MATURITY,
            RequestType::NeuronInfo { .. } => NEURON_INFO,
            RequestType::Follow { .. } => FOLLOW,
        }
    }

    pub const fn is_transfer(&self) -> bool {
        matches!(self, RequestType::Send)
    }
}

/// The type (encoded as CBOR) returned by /construction/combine, containing the
/// IC calls to submit the transaction and to check the result.
pub type SignedTransaction = Vec<Request>;

/// A vector of update/read-state calls for different ingress windows
/// of the same call.
pub type Request = (RequestType, Vec<EnvelopePair>);

/// A signed IC update call and the corresponding read-state call for
/// a particular ingress window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopePair {
    pub update: RequestEnvelope,
    pub read_state: RequestEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub content: EnvelopeContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_pubkey: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_sig: Option<Vec<u8>>,
}
