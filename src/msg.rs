use cosmwasm_std::{HumanAddr, Binary};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::contract::{BLOCK_SIZE};

use crate::viewing_key::ViewingKey;
use secret_toolkit::utils::{HandleCallback};  


/////////////////////////////////////////////////////////////////////////////////
// Init message
/////////////////////////////////////////////////////////////////////////////////

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub initseed: String,
    pub prng_seed: String,
}

/////////////////////////////////////////////////////////////////////////////////
// Handle messages
/////////////////////////////////////////////////////////////////////////////////

/// Handle messages. For RNG users, the three of these matter.
/// `callback_rn`: generates a random number in a single transaction.
/// `create_rn` and `fulfill_rn`: functions required for the two-transaction RNG.
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

// ------------------------------------------------------------------------------
// Enums for callback
// ------------------------------------------------------------------------------

/// User's contract needs a handle function in order to receive the random number.
/// A handle function called `receive_rn` is required to use the `callback_rn` RNG. 
/// A handle function called `receive_f_rn` is required to use the `fulfill_rn` RNG. 
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InterContractHandle{
    ReceiveRn {rn: [u8; 32], cb_msg: Binary},
    ReceiveFRn {rn: [u8; 32], cb_msg: Binary, purpose: Option<String>},
    DonateEntropy {entropy: String},
}

impl HandleCallback for InterContractHandle {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}


/////////////////////////////////////////////////////////////////////////////////
// Query messages
/////////////////////////////////////////////////////////////////////////////////

/// Query messages
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    QueryRn {entropy: String, addr: HumanAddr, vk: String},
    QueryConfig { },
}

impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&HumanAddr>, ViewingKey) {
        match self {
            Self::QueryRn {addr, vk, .. } => (vec![addr], ViewingKey(vk.clone())),
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
    /// Allows anyone to query the current configuration of the contract
    ContractConfig {
        // seed: [u8; 32],  //FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION!
        idx: u32,  // count of created rns via option 2
        forw_entropy: bool, // true=set to forward entropy
        fwd_entropy_hash: Vec<String>, // forward entropy hash
        fwd_entropy_addr: Vec<String>, // forward entropy addr
        admin: Vec<HumanAddr>, // admin addresses
        vk_perm_addr: Vec<HumanAddr>, // addresses that have been authenticated to generate VK
        vk_gen_addr: Vec<HumanAddr>, // address that have generated VK before
    }
}
