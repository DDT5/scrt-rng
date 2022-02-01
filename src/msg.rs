use cosmwasm_std::{HumanAddr, Binary};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::contract::{BLOCK_SIZE};

use crate::viewing_key::ViewingKey;
use secret_toolkit::utils::{HandleCallback};  

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub initseed: String,
    pub prng_seed: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    ConfigureFwd { 
        forw_entropy: bool,
        forw_entropy_to_hash: Vec<String>,
        forw_entropy_to_addr: Vec<String>,
    },
    ConfigureAuth {add: String},
    AddAdmin {add: String},
    RemoveAdmin {remove: String},

    DonateEntropy {entropy: String},

    RequestRn {entropy: String},

    CallbackRn {entropy: String, cb_msg: Binary, callback_code_hash: String, contract_addr: String},

    CreateRn {
        entropy: String, cb_msg: Binary, receiver_code_hash: String, 
        receiver_addr: Option<String>, purpose: Option<String>, max_blk_delay: Option<u64>,},
    FulfillRn {creator_addr: String, receiver_code_hash: String, purpose: Option<String>},

    ReceiveRn {rn: [u8; 32], cb_msg: Binary},

    GenerateViewingKey {
        entropy: String,
        receiver_code_hash: String,
        padding: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]  //PartialEq
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Rn {
        rn: [u8; 32],
    },
    ReceiveViewingKey {
        key: ViewingKey,
    },
}

impl HandleCallback for HandleAnswer {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    QueryRn {entropy: String},
    QueryAQuery {entropy: String, callback_code_hash: String, contract_addr: String},
    AuthQuery {entropy: String, addr: HumanAddr, vk: String},
    QueryConfig {what: u32},
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
    },
}
