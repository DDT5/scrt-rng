use schemars::JsonSchema;
// use serde::__private::de::IdentifierDeserializer;
// use schemars::_serde_json::Serializer;
use serde::{Deserialize, Serialize};  

use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier, debug_print,
    StdError, StdResult, QueryResult, 
    Storage, BankMsg, Coin, CosmosMsg, Uint128,
    HumanAddr, log
};

use crate::msg::{InitMsg, HandleMsg, HandleAnswer, QueryMsg, QueryAnswer}; //self
use crate::state::{
    State, load_state, save_state, write_viewing_key, read_viewing_key,
    // CONFIG_KEY,
};  
use crate::viewing_key::{ViewingKey}; //self, 
use crate::viewing_key::VIEWING_KEY_SIZE;

use secret_toolkit::utils::{pad_handle_result, pad_query_result, Query, HandleCallback}; //, InitCallback, 
use secret_toolkit::crypto::{sha_256};  //Prng

// use serde_json_wasm as serde_json;
// use x25519_dalek::{StaticSecret}; //PublicKey, 

use rand_chacha::ChaChaRng;
use rand::{Rng, SeedableRng}; //seq::SliceRandom,
use sha2::{Digest};
use std::convert::TryInto;

pub const STATE_KEY: &[u8] = b"state";
pub const BLOCK_SIZE: usize = 256;
pub const MIN_FEE: Uint128 = Uint128(100_000); /* 1mn uscrt = 1 SCRT */

/////////////////////////////////////////////////////////////////////////////////
// Enums for callback
/////////////////////////////////////////////////////////////////////////////////


// Calling handle in another contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveRnHandleMsg {
    ReceiveRn {rn: [u8; 32], cb_msg: Binary},
}

impl HandleCallback for ReceiveRnHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

// Calling query in another contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryRnMsg {
    QueryRn {entropy: String}
}

impl Query for QueryRnMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct RnOutput {
    pub rn: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct QueryAnswerMsg {
    pub rn_output: RnOutput,
}


/////////////////////////////////////////////////////////////////////////////////
// Init function
/////////////////////////////////////////////////////////////////////////////////

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    // Create initial seed
    let init_seed_arr = sha2::Sha256::digest(msg.initseed.as_bytes());
    let init_seed: [u8; 32] = init_seed_arr.as_slice().try_into().expect("Invalid");
    let state = State {
        seed: init_seed,
        prng_seed: sha_256(base64::encode(msg.prng_seed).as_bytes()).to_vec(),
        cb_msg: Binary(String::from("Here is an initial message String").as_bytes().to_vec()),
        cb_code_hash: env.contract_code_hash,
        contract_addr: env.contract.address.to_string()
    };

    //Save seed
    save_state(&mut deps.storage, STATE_KEY, &state)?;
    Ok(InitResponse::default())
}

/////////////////////////////////////////////////////////////////////////////////
// Handle functions
/////////////////////////////////////////////////////////////////////////////////

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult <HandleResponse> {
    let response = match msg {
        HandleMsg::EntropyString {entropy} => donate_entropy(deps, env, entropy),
        // HandleMsg::EntropyBool {entropy} => donate_entropy(deps, env, entropy),
        // HandleMsg::EntropyInt {entropy} => donate_entropy(deps, env, entropy),
        // HandleMsg::EntropyChar {entropy} => donate_entropy(deps, env, entropy),
        
        // HandleMsg::RnString {entropy} => call_rn(deps, env, entropy),
        // HandleMsg::RnBool {entropy} => call_rn(deps, env, entropy),
        // HandleMsg::RnInt {entropy} => call_rn(deps, env, entropy),
        // HandleMsg::RnChar {entropy} => call_rn(deps, env, entropy),

        HandleMsg::CallbackRn {
            entropy, cb_msg, callback_code_hash, contract_addr
        } => try_callback_rn(deps, env, entropy, cb_msg, callback_code_hash, contract_addr),

        HandleMsg::HcallbackRn {
            entropy, cb_msg, callback_code_hash, contract_addr
        } => try_hcallback_rn(deps, env, entropy, cb_msg, callback_code_hash, contract_addr),

        HandleMsg::ReceiveRn {
            rn, cb_msg
        } => try_receive_rn(deps, env, rn, cb_msg),

        HandleMsg::GenerateViewingKey {entropy, .. } => try_generate_viewing_key(deps, env, entropy),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

pub fn try_generate_viewing_key<S: Storage, A: Api, Q: Querier> (
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String
) -> StdResult<HandleResponse> {
    let config: State = load_state(&mut deps.storage, STATE_KEY)?;   // changed this from CONFIG_KEY
    let prng_seed = config.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;

    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::GenerateViewingKey {
            key,
        })?),
    })
}

pub fn donate_entropy<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T
) -> StdResult<HandleResponse> {
    // Load seed
    let mut state: State = load_state(&mut deps.storage, STATE_KEY)?;

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", state.seed, entropy, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    state.seed = new_seed;

    //Save State
    save_state(&mut deps.storage, STATE_KEY, &state)?;

    // get current contract incentive pool balance
    let denom = "uscrt";
    let balance = deps.querier.query_balance(&env.contract.address, denom).unwrap();

    // Create variables to feed into HandleResponse
    let balance_info = format!("Balance: {} of {}", balance.amount, balance.denom);
    let entropy_reward = Coin::new(
        // formula to determine reward size for calling donate_entropy
       balance.amount.u128()/100, 
        &balance.denom); 

    // debug print
    debug_print!("debug print here: thanks for donating entropy, {}", env.message.sender);

    Ok(HandleResponse {
        // reward payout for caller of donate_entropy 
        messages: vec![CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address,
            to_address: env.message.sender,
            amount: vec![entropy_reward], 
        })],
        log: vec![],
        // data for debugging purposes. Remove in final implementation 
        data: Some(to_binary(&balance_info)?),
    })
}

fn call_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: T
) -> StdResult<[u8; 32]> { 

    //Load state
    let mut state: State = load_state(&deps.storage, STATE_KEY)?;

    //Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", entropy, state.seed, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");

    //Save State
    state.seed = new_seed;
    save_state(&mut deps.storage, STATE_KEY, &state)?;

    //Generate random number -- chacha
    let mut rng = ChaChaRng::from_seed(new_seed);

    let mut dest: Vec<u8> = vec![0; 32];  // bytes as usize];
    for i in 0..dest.len() {
        dest[i] = rng.gen();
    }

    let rn_output: [u8; 32] = dest.try_into().expect("cannot");

    Ok(rn_output)
}

pub fn try_callback_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(   // 
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T,
    cb_msg: Binary,
    callback_code_hash: String,
    contract_addr: String
) -> StdResult<HandleResponse> {
    // need to transfer at least <fee amount> when requesting random number  
    if env.message.sent_funds.last().unwrap().amount
        < MIN_FEE
    || env.message.sent_funds.last().unwrap().denom != String::from("uscrt")
{
    return Err(StdError::generic_err(
        format!("Transferred amount:{}; coin:{}. Need to transfer {} uSCRT to generate random number.",
        env.message.sent_funds.last().unwrap().amount,
        env.message.sent_funds.last().unwrap().denom,
        MIN_FEE.u128()),
    ));
}

    // call generate RN function
    let rn_output = call_rn(deps, &env, entropy)?;

    // Send message back to consumer (to receive_rn)
    let receive_rn_msg = ReceiveRnHandleMsg::ReceiveRn {
        rn: rn_output,
        cb_msg: cb_msg
    };

    let cosmos_msg = receive_rn_msg.to_cosmos_msg(
        callback_code_hash.to_string(), 
        HumanAddr(contract_addr.to_string()), 
        None
    )?;

    // let cb_resp_data = to_binary(&HandleAnswer::Rn {
    //     rn: query_ans.rn_output.rn,
    // });

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![],
        data: None
        // data: Some(cb_resp_data?),
    })

    // Ok(HandleResponse::default())
}

pub fn try_hcallback_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T,
    cb_msg: Binary,
    callback_code_hash: String,
    contract_addr: String
) -> StdResult<HandleResponse> {
    // need to transfer at least <fee amount> when requesting random number  
    if env.message.sent_funds.last().unwrap().amount
        < MIN_FEE
    || env.message.sent_funds.last().unwrap().denom != String::from("uscrt")
{
    return Err(StdError::generic_err(
        format!("Transferred amount:{}; coin:{}. Need to transfer {} uSCRT to generate random number.",
        env.message.sent_funds.last().unwrap().amount,
        env.message.sent_funds.last().unwrap().denom,
        MIN_FEE.u128()),
    ));
}

    // call generate RN function
    let rn_output = call_rn(deps, &env, entropy)?;

    // trigger callback for previous user
    //Load state
    let mut state: State = load_state(&deps.storage, STATE_KEY)?;
    let prev_cb_msg = state.cb_msg;
    let prev_callback_code_hash = state.cb_code_hash;
    let prev_contract_addr = state.contract_addr;

    //save state
    state.cb_msg = cb_msg;
    state.cb_code_hash = callback_code_hash;
    state.contract_addr = contract_addr; 
    save_state(& mut deps.storage, STATE_KEY, &state)?;

    // Send message back to consumer (to receive_rn)
    let receive_rn_msg = ReceiveRnHandleMsg::ReceiveRn {
        rn: rn_output,
        cb_msg: prev_cb_msg
    };

    // let cosmos_msg_option = receive_rn_msg.to_cosmos_msg(
    //     prev_callback_code_hash.to_string(), 
    //     HumanAddr(prev_contract_addr.to_string()), 
    //     None
    // )?;

    let cosmos_msg_option = receive_rn_msg.to_cosmos_msg(
        prev_callback_code_hash.to_string(), 
        HumanAddr(prev_contract_addr.to_string()), 
        None
    );

    let cosmos_msg = match cosmos_msg_option {
        Ok(i) => i,
        Err(_) => return Err(StdError::generic_err("cosmos message for callback could not be created")),
    };

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![],
        data: None
    })

    // Ok(HandleResponse::default())
}



pub fn try_receive_rn<S: Storage, A: Api, Q: Querier>(  // RN consumer's handle message that continues the code
    deps: &mut Extern<S, A, Q>,
    env: Env,
    rn: [u8; 32],
    cb_msg: Binary,
) -> StdResult<HandleResponse> {
    // let mut config: Config = load(&deps.storage, CONFIG_KEY)?;
    // let apprv_sender = config.apprv_sender;
    let apprv_sender = deps.api.canonical_address(&env.contract.address)?;  //<-- for user contract, set to scrt-rng's contract addr
    let sender = deps.api.canonical_address(&env.message.sender)?;
    if apprv_sender != sender {
        return Err(StdError::generic_err(
            "receive_rn did not approve sender address",
        ));
    }
    
    let consumer_output = format!("Original message: {:?}, combined with rn: {:?}", 
    String::from_utf8(cb_msg.as_slice().to_vec()),   // <-- will only display properly if the cb_msg input is a String
    rn);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("output", consumer_output)],
        data: None,
    })
}

/////////////////////////////////////////////////////////////////////////////////
// Query functions 
/////////////////////////////////////////////////////////////////////////////////

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {  // StdResult<Binary> , QueryResult
    let response = match msg {
        QueryMsg::QueryRn {entropy} => try_query_rn(deps, entropy),
        QueryMsg::QueryAQuery {entropy, callback_code_hash, contract_addr} => try_query_a_query(deps, entropy, callback_code_hash, contract_addr),
        QueryMsg::QueryDebug {which} => try_query_debug(deps, which), // <-- FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION
        _ => authenticated_queries(deps, msg),
   };
   pad_query_result(response, BLOCK_SIZE)
}

pub fn try_query_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &Extern<S, A, Q>,
    entropy: T,
) -> QueryResult {
    // Load seed
    let state: State = load_state(&deps.storage, STATE_KEY)?; // remove `mut`

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}", state.seed, entropy);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    
    //Generate random number -- chacha
    let mut rng = ChaChaRng::from_seed(new_seed);

    let mut dest: Vec<u8> = vec![0; 32];  // bytes as usize];
    for i in 0..dest.len() {
        dest[i] = rng.gen();
    }

    let rn_output: [u8; 32] = dest.try_into().expect("cannot");

    to_binary(&QueryAnswer::RnOutput{rn: rn_output})

}

pub fn try_query_a_query<S: Storage, A: Api, Q:Querier>(
    deps: &Extern<S, A, Q>,
    entropy: String,
    callback_code_hash: String, 
    contract_addr: String
) -> QueryResult {
    let query_msg = QueryRnMsg::QueryRn {entropy: entropy};
    let query_ans: QueryAnswerMsg = query_msg.query(   //: StdResult<Binary>   QueryAnswerMsg 
        &deps.querier, 
        callback_code_hash.to_string(), 
        HumanAddr(contract_addr.to_string()),
    )?;

    to_binary(&QueryAnswer::RnOutput{rn: query_ans.rn_output.rn})
    
}


pub fn try_query_debug<S: Storage, A: Api, Q: Querier>(
    _deps: &Extern<S, A, Q>,
    _which: u32
) -> QueryResult {
//FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION//////
    // let state: State = load_state(&deps.storage, STATE_KEY)?;
    // match which {
    //     0 => return to_binary(&format!("seed: {:?}", state.seed)),
    //     1 => return to_binary(&format!("cb_msg: {:?}", String::from_utf8(state.cb_msg.as_slice().to_vec()))),
    //     2 => return to_binary(&format!("code hash: {:}", state.cb_code_hash)),
    //     3 => return to_binary(&format!("contract addr: {:}", state.contract_addr)),
    //     _ => return Err(StdError::generic_err("invalid number. Try 0-3"))
    // };

    // to_binary(&QueryAnswer::Seed{seed: state.seed})

    // /////////////////////////////////////////////////////////// 

    to_binary(&QueryAnswer::RnOutput{rn: [0; 32]})

}



/////////////////////////////////////////////////////////////////////////////////
// Authenticated Queries 
/////////////////////////////////////////////////////////////////////////////////

fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;
        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                QueryMsg::AuthQuery {addr, entropy, ..} => try_authquery(&deps, entropy, &addr),
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Err(StdError::unauthorized())
}

fn try_authquery<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &Extern<S, A, Q>,
    entropy: T,
    _addr: &HumanAddr,
    // vk: String,
) -> StdResult<Binary> {
    // Load seed
    let state: State = load_state(&deps.storage, STATE_KEY)?; // remove `mut`

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}", state.seed, entropy);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    
    //Generate random number -- chacha
    let mut rng = ChaChaRng::from_seed(new_seed);

    let mut dest: Vec<u8> = vec![0; 32];  // bytes as usize];
    for i in 0..dest.len() {
        dest[i] = rng.gen();
    }

    let rn_output: [u8; 32] = dest.try_into().expect("cannot");

    to_binary(&QueryAnswer::RnOutput{rn: rn_output})
}


/////////////////////////////////////////////////////////////////////////////////
// Unit tests
/////////////////////////////////////////////////////////////////////////////////

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use cosmwasm_std::testing::{mock_dependencies, mock_env};
//     use cosmwasm_std::{coins, StdError};  //, from_binary
//     // use serde::__private::de::IdentifierDeserializer;

//     #[test]
//     fn call_rn_changes_rn() {
//         let mut deps = mock_dependencies(20, &coins(2, "token"));

//         let env = mock_env("creator", &coins(2, "token"));
//         let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed")};
//         let _res = init(&mut deps, env, msg).unwrap();
        
//         let env = mock_env("RN user", &coins(MIN_FEE.u128(), "uscrt"));
//         let msg = HandleMsg::RnString {entropy: String::from("String input")};
//         let res1 = call_rn(&mut deps, env, msg).unwrap().data;
        
//         let env = mock_env("RN user", &coins(MIN_FEE.u128(), "uscrt"));
//         let msg = HandleMsg::RnString {entropy: String::from("String input")};
//         let res2 = call_rn(&mut deps, env, msg).unwrap().data;

//         assert_ne!(res1, res2);
//     }

//     #[test]
//     fn call_rn_requires_min_fee() {
//         let mut deps = mock_dependencies(20, &coins(2, "token"));

//         let env = mock_env("creator", &coins(2, "token"));
//         let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed")};
//         let _res = init(&mut deps, env, msg).unwrap();
        
//         let env = mock_env("RN user", &coins(MIN_FEE.u128()-1, "uscrt"));
//         let msg = HandleMsg::RnString {entropy: String::from("String input")};
//         let res = call_rn(&mut deps, env, msg);

//         match res {
//             Err(StdError::GenericErr {..}) => {}
//             _ => panic!("Should return inadequate fee error"),
//         }
//     }

//     #[test]
//     fn donate_entropy_changes_seed() {
//         // WIP
//     }
// }
