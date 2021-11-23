use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InitMsg {
    pub initseed: String
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    EntropyString {entropy: String},
    EntropyBool {entropy: bool},
    EntropyInt {entropy: i32},
    EntropyChar {entropy: char},
    
    RnString {entropy: String},
    RnBool {entropy: bool},
    RnInt {entropy: i32},
    RnChar {entropy: char},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Rn {
        rn: [u8; 32],
        // privkey: [u8; 32],
        blocktime: u64
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    RnQuery { }
}

/// Responses from query function
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    RnOutput {
        info: String
    }
}
