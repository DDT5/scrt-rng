use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier,  //debug_print, 
    StdError, StdResult, Storage,
    BankMsg, Coin, CosmosMsg, Uint128
};

use crate::msg::{InitMsg, HandleMsg, HandleAnswer, QueryMsg, QueryAnswer};
use crate::state::{State, load_seed, save_seed};

// use serde_json_wasm as serde_json;
use x25519_dalek::{StaticSecret}; //PublicKey, 

// use rand::{Rng, SeedableRng}; //seq::SliceRandom,
// use rand_chacha::ChaChaRng;
use sha2::{Digest};
use std::convert::TryInto;

pub const STATE_KEY: &[u8] = b"state";
pub const MIN_FEE: Uint128 = Uint128(100_000); /* 1mn uscrt = 1 SCRT */

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    // Create initial seed
    let init_seed_arr = sha2::Sha256::digest(msg.initseed.as_bytes());
    let init_seed: [u8; 32] = init_seed_arr.as_slice().try_into().expect("Invalid");
    let state = State {
        seed: init_seed,
    };

    //Save seed
    save_seed(&mut deps.storage, STATE_KEY, &state)?;
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
    match msg {
        HandleMsg::EntropyString {entropy} => donate_entropy(deps, env, entropy),
        HandleMsg::EntropyBool {entropy} => donate_entropy(deps, env, entropy),
        HandleMsg::EntropyInt {entropy} => donate_entropy(deps, env, entropy),
        HandleMsg::EntropyChar {entropy} => donate_entropy(deps, env, entropy),
        
        HandleMsg::RnString {entropy} => get_rn(deps, env, entropy),
        HandleMsg::RnBool {entropy} => get_rn(deps, env, entropy),
        HandleMsg::RnInt {entropy} => get_rn(deps, env, entropy),
        HandleMsg::RnChar {entropy} => get_rn(deps, env, entropy),
    }
}

pub fn donate_entropy<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T
) -> StdResult <HandleResponse> {
    // Load seed
    let mut state: State = load_seed(&mut deps.storage, STATE_KEY)?;

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", state.seed, entropy, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    state.seed = new_seed;

    //Save State
    save_seed(&mut deps.storage, STATE_KEY, &state)?;

    // get current contract incentive pool balance
    let denom = "uscrt";
    let balance = deps.querier.query_balance(&env.contract.address, denom).unwrap();

    // Create variables to feed into HandleResponse
    let balance_info = format!("Balance: {} of {}", balance.amount, balance.denom);
    let entropy_reward = Coin::new(
        // formula to determine reward size for calling donate_entropy
       balance.amount.u128()/100, 
        &balance.denom); 

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

pub fn get_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T
) -> StdResult <HandleResponse> { // HandleResult<HandleResponse> {

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
    //Load state
    let mut state: State = load_seed(&deps.storage, STATE_KEY)?;

    //Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", entropy, state.seed, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");

    //Save State
    state.seed = new_seed;
    save_seed(&mut deps.storage, STATE_KEY, &state)?;

    //Generate random number
    // let rn_output: [u8;32] = ChaChaRng::from_seed(new_seed).gen();
    let rn_output= StaticSecret::from(new_seed);

    // Change random number to binary
    let resp_data = to_binary(&HandleAnswer::Rn {
        // rn: rn_output,
        rn: rn_output.to_bytes(),
        // Debugging - Remove blocktime eventually
        blocktime: env.block.time,
    });

    Ok(HandleResponse {
        messages: vec![],
        // log: vec![log("Output", resp_log)], <-- eventually remove this
        log: vec![],
        data: Some(resp_data?),
    })
     
}

/////////////////////////////////////////////////////////////////////////////////
// Query functions 
/////////////////////////////////////////////////////////////////////////////////

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> StdResult<Binary> {
    match msg {
        QueryMsg::RnQuery { } => placeholder_rn_query(deps),
   }
}

pub fn placeholder_rn_query<S: Storage, A: Api, Q: Querier>(
    _deps: &Extern<S, A, Q>,
) -> StdResult<Binary> {

    let mut data = String::new();
    data.push_str("Secret Oracle - RNG");
    to_binary(&QueryAnswer::RnOutput{info: data})

    //FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION//////
    // let state: State = load(&deps.storage, STATE_KEY)?;
    // to_binary(&QueryAnswer::Info{info:format!("{:?}",state.seed)})
    //--////////////////////////////////////////////////////////// 

}

/////////////////////////////////////////////////////////////////////////////////
// Unit test
/////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, StdError};  //, from_binary
    // use serde::__private::de::IdentifierDeserializer;

    #[test]
    fn get_rn_changes_rn() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String")};
        let _res = init(&mut deps, env, msg).unwrap();
        
        let env = mock_env("RN user", &coins(MIN_FEE.u128(), "uscrt"));
        let msg = HandleMsg::RnString {entropy: String::from("String input")};
        let res1 = get_rn(&mut deps, env, msg).unwrap().data;
        
        let env = mock_env("RN user", &coins(MIN_FEE.u128(), "uscrt"));
        let msg = HandleMsg::RnString {entropy: String::from("String input")};
        let res2 = get_rn(&mut deps, env, msg).unwrap().data;

        assert_ne!(res1, res2);
    }

    #[test]
    fn get_rn_requires_min_fee() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String")};
        let _res = init(&mut deps, env, msg).unwrap();
        
        let env = mock_env("RN user", &coins(MIN_FEE.u128()-1, "uscrt"));
        let msg = HandleMsg::RnString {entropy: String::from("String input")};
        let res = get_rn(&mut deps, env, msg);

        match res {
            Err(StdError::GenericErr {..}) => {}
            _ => panic!("Should return inadequate fee error"),
        }
    }

    #[test]
    fn donate_entropy_changes_seed() {
        // WIP
    }
}
