use cosmwasm_std::HumanAddr;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::viewing_key::ViewingKey;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub initseed: String,
    pub prng_seed: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    EntropyString {entropy: String},
    // EntropyBool {entropy: bool},
    // EntropyInt {entropy: i32},
    // EntropyChar {entropy: char},
    
    RnString {entropy: String},
    // RnBool {entropy: bool},
    // RnInt {entropy: i32},
    // RnChar {entropy: char},

    Callback {entropy: String, callback_code_hash: String, contract_addr: String},

    GenerateViewingKey {
        entropy: String,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]  //, PartialEq
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Rn {
        rn: [u8; 32],
        // blocktime: u64
    },
    GenerateViewingKey {
        key: ViewingKey,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    QueryRn {entropy: String},
    QueryAQuery {entropy: String, callback_code_hash: String, contract_addr: String},
    AuthQuery {entropy: String, addr: HumanAddr, vk: String}
}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&HumanAddr>, ViewingKey) {
        match self {
            Self::AuthQuery {addr, vk, .. } => (vec![addr], ViewingKey(vk.clone())),
            _ => panic!("This query type does not require authentication")
        }
    }
}

/// Responses from query function
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    RnOutput {
        rn: [u8; 32],
    }
}
