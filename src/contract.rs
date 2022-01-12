use schemars::JsonSchema;
// use serde::__private::de::IdentifierDeserializer;
// use schemars::_serde_json::Serializer;
use serde::{Deserialize, Serialize};  

use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier, debug_print,
    StdError, StdResult, QueryResult, 
    Storage, BankMsg, Coin, CosmosMsg, Uint128,
    HumanAddr, log, CanonicalAddr
};

use crate::msg::{InitMsg, HandleMsg, HandleAnswer, QueryMsg, QueryAnswer}; //self
use crate::state::{
    Seed, CbMsg, EntrpChk, Admins, ForwEntrpConfig, PrngSeed, CbMsgConfig, 
    load_state, save_state, write_viewing_key, read_viewing_key, idx_read, idx_write, write_cb_msg, read_cb_msg,
    SEED_KEY, CONFIG_KEY, ADMIN_KEY, ENTRP_CHK_KEY, PRNG_KEY, CB_CONFIG_KEY,
};  
use crate::viewing_key::{ViewingKey}; //self, 
use crate::viewing_key::VIEWING_KEY_SIZE;

use secret_toolkit::utils::{pad_handle_result, pad_query_result, Query, HandleCallback}; //, InitCallback, 
use secret_toolkit::crypto::{sha_256};  //Prng

// use serde_json_wasm as serde_json;

use rand_chacha::ChaChaRng;
use rand::{Rng, SeedableRng}; //seq::SliceRandom,
use sha2::{Digest};
use std::convert::TryInto;

pub const BLOCK_SIZE: usize = 256;
pub const MIN_FEE: Uint128 = Uint128(100_000); /* 1mn uscrt = 1 SCRT */

/////////////////////////////////////////////////////////////////////////////////
// Enums for callback
/////////////////////////////////////////////////////////////////////////////////


// Calling receive_rn handle in user's contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveRnHandleMsg {
    ReceiveRn {rn: [u8; 32], cb_msg: Binary},
}

impl HandleCallback for ReceiveRnHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

// Calling forward_rn handle in rng-interface's contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FwdRnHandleMsg {
    FwdRn {rn: [u8; 32], usr_cb_msg: Binary, usr_hash: String, usr_addr: CanonicalAddr},
}

impl HandleCallback for FwdRnHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}


// Calling donate_entropy in another contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DonateEntropyMsg {
    DonateEntropy {entropy: String},
}

impl HandleCallback for DonateEntropyMsg {
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
    // Init seed -----------------------------------------------------------------
    let init_seed_arr = sha2::Sha256::digest(msg.initseed.as_bytes());
    let init_seed: [u8; 32] = init_seed_arr.as_slice().try_into().expect("Invalid");
    let seed = Seed {
        seed: init_seed
    };
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

    // init other variables ------------------------------------------------------
    let admin = Admins {
        admins: vec![deps.api.canonical_address(&env.message.sender)?],
    };
    save_state(&mut deps.storage, ADMIN_KEY, &admin)?;

    let entrp_chk = EntrpChk {
        forw_entropy_check: false,
    };
    save_state(&mut deps.storage, ENTRP_CHK_KEY, &entrp_chk)?;

    let config = ForwEntrpConfig {
        forw_entropy_to_hash: String::default(),
        forw_entropy_to_addr: String::default(),
    };
    save_state(&mut deps.storage, CONFIG_KEY, &config)?;

    let pseed = PrngSeed {
        prng_seed: sha_256(base64::encode(msg.prng_seed).as_bytes()).to_vec(),
    };
    save_state(&mut deps.storage, PRNG_KEY, &pseed)?;

    // Init CbMsg for h_callback_rn ----------------------------------------------
    let cb_msg_config = CbMsgConfig {
        rng_interface_hash: String::default(), // to be properly set later through config
        rng_interface_addr: CanonicalAddr::default(), // to be properly set later through config
        cb_offset: msg.cb_offset,
    };
    save_state(&mut deps.storage, CB_CONFIG_KEY, &cb_msg_config)?;

    let usr_cb_store = CbMsg {
        usr_hash: env.contract_code_hash.to_string(), // sends to receive_rn function in scrt-rng contract
        usr_addr: deps.api.canonical_address(&env.contract.address)?,
        usr_cb_msg: Binary(String::from("initial cb_msg").as_bytes().to_vec()),
    };

    // loop to initialize cb_msg storage based on callback_offset
    let mut id = 0u32;
    while id < msg.cb_offset {
        write_cb_msg(&mut deps.storage, &id, &usr_cb_store)?;
        id += 1;
    }

    // initialize cb_msg index (pointer) to 0
    idx_write(&mut deps.storage).save(&0u32)?;

    
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
        HandleMsg::Configure {
            forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr, interf_hash, interf_addr, cb_offset,
        } => try_configure(deps, env, forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr, interf_hash, interf_addr, cb_offset,),

        HandleMsg::AddAdmin {add} => try_add_admin(deps, env, add),
        HandleMsg::RemoveAdmin {remove} => try_remove_admin(deps, env, remove),

        HandleMsg::DonateEntropy {entropy} => donate_entropy(deps, env, entropy),
        HandleMsg::DonateEntropyRwrd {entropy} => donate_entropy_rwrd(deps, env, entropy),

        HandleMsg::CallbackRn {
            entropy, cb_msg, callback_code_hash, contract_addr
        } => try_callback_rn(deps, env, entropy, cb_msg, callback_code_hash, contract_addr),

        HandleMsg::HCallbackRn {
            entropy, cb_msg, callback_code_hash, contract_addr
        } => try_h_callback_rn(deps, env, entropy, cb_msg, callback_code_hash, contract_addr),

        HandleMsg::ReceiveRn {
            rn, cb_msg
        } => try_receive_rn(deps, env, rn, cb_msg),

        HandleMsg::GenerateViewingKey {entropy, .. } => try_generate_viewing_key(deps, env, entropy),

        HandleMsg::HandleAQuery {entropy, callback_code_hash, contract_addr} => try_handle_a_query(deps, entropy, callback_code_hash, contract_addr),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn try_configure<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    forw_entropy: bool,
    forw_entropy_to_hash: String,
    forw_entropy_to_addr: String,
    interf_hash: String,
    interf_addr: String,
    cb_offset: u32,
) -> StdResult<HandleResponse> {
    // check if admin
    let admins_vec: Admins = load_state(&mut deps.storage, ADMIN_KEY)?;
    let admins = &admins_vec.admins;
    let sender = &deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender) {
        return Err(StdError::generic_err(
            "This is an admin function",
        ));
    }

    // Change config for rng-interface (for forwarding cb_msg)
    let new_cb_msg_config = CbMsgConfig {
        rng_interface_hash: interf_hash,
        rng_interface_addr: deps.api.canonical_address(&HumanAddr(interf_addr))?,
        cb_offset: cb_offset,
    };
    save_state(&mut deps.storage, CB_CONFIG_KEY, &new_cb_msg_config)?;

    // change Forward Entropy Config
    let new_entrp_chk = EntrpChk {
        forw_entropy_check: forw_entropy
    };
    let new_config = ForwEntrpConfig {
        forw_entropy_to_hash: forw_entropy_to_hash,
        forw_entropy_to_addr: forw_entropy_to_addr,
    };
    save_state(&mut deps.storage, ENTRP_CHK_KEY, &new_entrp_chk)?;
    save_state(&mut deps.storage, CONFIG_KEY, &new_config)?;

    Ok(HandleResponse::default())
}

fn try_add_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    add: String,
) -> StdResult<HandleResponse> {
    // check if admin
    let mut admins_vec: Admins = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_admin(deps, &env, &admins_vec)?;
    
    // add admin
    admins_vec.admins.extend(deps.api.canonical_address(&HumanAddr(add)));
    save_state(&mut deps.storage, ADMIN_KEY, &admins_vec.admins)?;

    Ok(HandleResponse::default())
}

fn try_remove_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    remove: String,
) -> StdResult<HandleResponse> {
    // check if admin
    let mut admins_vec: Admins = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_admin(deps, &env, &admins_vec)?;

    // cannot remove creator
    let remove_canon = deps.api.canonical_address(&HumanAddr(remove))?;
    if remove_canon == admins_vec.admins[0] {
        return Err(StdError::generic_err(
            "Cannot remove creator as admin"
        ));
    }

    // remove admin
    admins_vec.admins.retain(|x| x != &remove_canon);
    save_state(&mut deps.storage, ADMIN_KEY, &admins_vec.admins)?;

    Ok(HandleResponse::default())
}

fn check_admin<S: Storage, A: Api, Q:Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    admins_vec: &Admins, 
) -> StdResult<()> {
    let admins = &admins_vec.admins;
    let sender = &deps.api.canonical_address(&env.message.sender)?;
    if !admins.contains(&sender) {
        return Err(StdError::generic_err(
            "This is an admin function",
        ));
    }
    Ok(())
}

fn call_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: T
) -> StdResult<[u8; 32]> { 
    debug_print!("call_rn: initiated");

    //Load state (seed)
    let mut seed: Seed = load_state(&deps.storage, SEED_KEY)?;

    //Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", entropy, seed.seed, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");

    //Save Seed
    seed.seed = new_seed;
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

    //Generate random number -- chacha
    let mut rng = ChaChaRng::from_seed(new_seed);

    let mut dest: Vec<u8> = vec![0; 32];  // bytes as usize];
    for i in 0..dest.len() {
        dest[i] = rng.gen();
    }

    let rn_output: [u8; 32] = dest.try_into().expect("cannot");

    Ok(rn_output)
}

fn forward_entropy<S: Storage, A: Api, Q:Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    _env: &Env,
    entropy: &T,
) -> StdResult<CosmosMsg> {
    debug_print!("forward entropy: initiated");
    let entrp_chk: EntrpChk = load_state(&deps.storage, ENTRP_CHK_KEY)?;
    debug_print!("forward entropy: marker 2");

    if entrp_chk.forw_entropy_check == true {
        debug_print!("forward entropy: marker 3");
        let config: ForwEntrpConfig = load_state(&deps.storage, CONFIG_KEY)?;
        let entropy_hashed_full = &sha2::Sha256::digest(format!("{:?}", &entropy).as_bytes());
        // forward a String of the first 32 bits; saves a bit of gas vs sending the whole 256bit String:
        let entropy_hashed = &entropy_hashed_full.as_slice()[0..4]; 
        let donate_entropy_msg = DonateEntropyMsg::DonateEntropy {
            entropy: format!("{:?}", &entropy_hashed),
        };
        debug_print!("entropy String forwarded: {:?}", entropy_hashed);
        let cosmos_msg = donate_entropy_msg.to_cosmos_msg(
        config.forw_entropy_to_hash.to_string(), 
        HumanAddr(config.forw_entropy_to_addr.to_string()), 
        None
        );
        cosmos_msg
    }
    else {
        debug_print!("forward entropy: marker 4");
        return Err(StdError::generic_err("forward entropy bool value set to false"));
    }
}


pub fn try_generate_viewing_key<S: Storage, A: Api, Q: Querier> (
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String
) -> StdResult<HandleResponse> {
    let config: PrngSeed = load_state(&mut deps.storage, PRNG_KEY)?;   // changed this from CONFIG_KEY
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

pub fn donate_entropy<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(  // donate entropy without reward; computationally lighter
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T
) -> StdResult<HandleResponse> {
    // Load seed
    let mut seed: Seed = load_state(&mut deps.storage, SEED_KEY)?;

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", seed.seed, entropy, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    seed.seed = new_seed;

    //Save Seed
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

    // debug print
    debug_print!("entropy successfully forwarded, from {} to {}", env.message.sender, env.contract.address);

    Ok(HandleResponse::default())
}

pub fn donate_entropy_rwrd<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(  // donate entropy with reward
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T
) -> StdResult<HandleResponse> {
    // Load seed
    let mut seed: Seed = load_state(&mut deps.storage, SEED_KEY)?;

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", seed.seed, entropy, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    seed.seed = new_seed;

    //Save Seed
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

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
    debug_print!("debug print here: thanks for donating entropy, here's your reward, {}", env.message.sender);

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

pub fn try_callback_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(   // 
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T,
    cb_msg: Binary,
    callback_code_hash: String,
    contract_addr: String
) -> StdResult<HandleResponse> {
    debug_print!("try_callback_rn: initiated");
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

    debug_print!("try_callback_rn: passed fee check");
    // call generate RN function
    let rn_output = call_rn(deps, &env, &entropy)?;

    debug_print!("try_callback_rn: passed call_rn");

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

    //Potentially forward entropy to another contract
    debug_print!("try_callback_rn: forward entropy initiated");
    let cosmos_msg_fwd_entropy = forward_entropy(deps, &env, &entropy);
    debug_print!("try_callback_rn: forward entropy done");

    // let cb_resp_data = to_binary(&HandleAnswer::Rn {
    //     rn: query_ans.rn_output.rn,
    // });

    // create multiple messages
    let messages = match cosmos_msg_fwd_entropy {
        Ok(i) => vec![cosmos_msg, i],
        Err(_) => vec![cosmos_msg],
    };

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None
        // data: Some(cb_resp_data?),
    })

    // Ok(HandleResponse::default())
}

pub fn try_h_callback_rn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
    cb_msg: Binary,
    usr_hash: String,
    usr_addr: String,
) -> StdResult<HandleResponse> {
    // load CbMsgConfig and the current idx (the one to be executed)
    let config: CbMsgConfig = load_state(&deps.storage, CB_CONFIG_KEY)?;
    let idx = idx_read(&deps.storage).load()?;

    // save new idx (pointer); and save cb_msg and usr_hash and usr_addr
    let idx_save = idx.wrapping_add(config.cb_offset);
    idx_write(&mut deps.storage).save(&idx_save)?;

    let usr_cb_store = CbMsg {
        usr_hash: usr_hash,
        usr_addr: deps.api.canonical_address(&HumanAddr(usr_addr))?,
        usr_cb_msg: cb_msg,
    };
    write_cb_msg(&mut deps.storage, &idx_save, &usr_cb_store)?;

    // call generate RN function
    let rn_output = call_rn(deps, &env, &entropy)?;

    // Load (previous user) CbMsg info based on idx 
    let prev_usr_msg = read_cb_msg(&deps.storage, &idx)?;
    
    // call fwd_rn handle function in rng-interface's contract
    let fwd_rn_msg = FwdRnHandleMsg::FwdRn {
        rn: rn_output,
        usr_hash: prev_usr_msg.usr_hash,
        usr_addr: prev_usr_msg.usr_addr,
        usr_cb_msg: prev_usr_msg.usr_cb_msg,
    };

    let cosmos_msg = fwd_rn_msg.to_cosmos_msg(
        config.rng_interface_hash,
        deps.api.human_address(&config.rng_interface_addr)?, 
        None
    )?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![],
        data: None
    })

    // Ok(HandleResponse::default())
}

// cb_msg offset = 1 ==========================================================
// Put this in init handle function if using this code 
    // let cbm_store = CbMsg {
    //     usr_hash: env.contract_code_hash,
    //     usr_addr: deps.api.canonical_address(&env.contract.address)?,
    //     usr_cb_msg: Binary(String::from("Here is an initial message String").as_bytes().to_vec()),
    // }; 
    // save_state(&mut deps.storage, CB_MSG_KEY, &cbm_store)?;
// ============================================================================
// pub fn try_h_callback_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
//     deps: &mut Extern<S, A, Q>,
//     env: Env,
//     entropy: T,
//     cb_msg: Binary,
//     callback_code_hash: String,
//     contract_addr: String
// ) -> StdResult<HandleResponse> {
//     // need to transfer at least <fee amount> when requesting random number  
//     if env.message.sent_funds.last().unwrap().amount
//         < MIN_FEE
//     || env.message.sent_funds.last().unwrap().denom != String::from("uscrt")
// {
//     return Err(StdError::generic_err(
//         format!("Transferred amount:{}; coin:{}. Need to transfer {} uSCRT to generate random number.",
//         env.message.sent_funds.last().unwrap().amount,
//         env.message.sent_funds.last().unwrap().denom,
//         MIN_FEE.u128()),
//     ));
// }

//     // call generate RN function
//     let rn_output = call_rn(deps, &env, entropy)?;

//     // trigger callback for previous user
//     //Load state
//     let mut cbm_store: CbMsg = load_state(&deps.storage, CB_MSG_KEY)?;
//     let prev_callback_code_hash = cbm_store.usr_hash;
//     let prev_contract_addr = cbm_store.usr_addr;
//     let prev_cb_msg = cbm_store.usr_cb_msg;

//     //save cbm_store
//     cbm_store.usr_hash = callback_code_hash;
//     cbm_store.usr_addr = deps.api.canonical_address(&HumanAddr(contract_addr))?; 
//     cbm_store.usr_cb_msg = cb_msg;
//     save_state(& mut deps.storage, CB_MSG_KEY, &cbm_store)?;

//     // Send message back to consumer (to receive_rn)
//     let receive_rn_msg = ReceiveRnHandleMsg::ReceiveRn {
//         rn: rn_output,
//         cb_msg: prev_cb_msg
//     };

//     // let cosmos_msg_option = receive_rn_msg.to_cosmos_msg(
//     //     prev_callback_code_hash.to_string(), 
//     //     HumanAddr(prev_contract_addr.to_string()), 
//     //     None
//     // )?;

//     let cosmos_msg_option = receive_rn_msg.to_cosmos_msg(
//         prev_callback_code_hash.to_string(), 
//         HumanAddr(prev_contract_addr.to_string()), 
//         None
//     );

//     let cosmos_msg = match cosmos_msg_option {
//         Ok(i) => i,
//         Err(_) => return Err(StdError::generic_err("cosmos message for callback could not be created")),
//     };

//     Ok(HandleResponse {
//         messages: vec![cosmos_msg],
//         log: vec![],
//         data: None
//     })

//     // Ok(HandleResponse::default())
// }

pub fn try_receive_rn<S: Storage, A: Api, Q: Querier>(  // RN consumer's handle message that continues the code
    _deps: &mut Extern<S, A, Q>,
    _env: Env,
    rn: [u8; 32],
    cb_msg: Binary,
) -> StdResult<HandleResponse> {
    
    let consumer_output = format!("Original message: {:?}, combined with rn: {:?}", 
    String::from_utf8(cb_msg.as_slice().to_vec()),   // <-- will only display properly if the cb_msg input is a String
    rn);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("output", consumer_output)],
        data: None,
    })
}

pub fn try_handle_a_query<S: Storage, A: Api, Q:Querier>(
    deps: &Extern<S, A, Q>,
    entropy: String,
    callback_code_hash: String, 
    contract_addr: String
) -> StdResult<HandleResponse> {
    let query_msg = QueryRnMsg::QueryRn {entropy: entropy};
    let query_ans: QueryAnswerMsg = query_msg.query(   //: StdResult<Binary>   QueryAnswerMsg 
        &deps.querier, 
        callback_code_hash.to_string(), 
        HumanAddr(contract_addr.to_string()),
    )?;

    let output_log = format!("{:?}", query_ans.rn_output.rn);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("output", output_log)],
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
    let seed: Seed = load_state(&deps.storage, SEED_KEY)?; // remove `mut`

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}", seed.seed, entropy);
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
    deps: &Extern<S, A, Q>,
    which: u32
) -> QueryResult {
//FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION//////
    let seed: Seed = load_state(&deps.storage, SEED_KEY)?;
    let idx: u32 = idx_read(&deps.storage).load()?;
    let cbm_store: CbMsg = read_cb_msg(&deps.storage, &idx)?;
    let admins: Admins = load_state(&deps.storage, ADMIN_KEY)?;
    let entrp_chk: EntrpChk = load_state(&deps.storage, ENTRP_CHK_KEY)?;
    let config: ForwEntrpConfig = load_state(&deps.storage, CONFIG_KEY)?;

    // Human Addr for admins
    let mut admin_human: Vec<HumanAddr> = vec![];
    for admin in admins.admins {
        admin_human.push(deps.api.human_address(&admin)?)
    }

    match which {
        0 => return to_binary(&format!("seed: {:?}", seed.seed)),
        1 => return to_binary(&format!("cb_msg user code hash: {:}", cbm_store.usr_hash)),
        2 => return to_binary(&format!("cb_msg user addr: {:}", cbm_store.usr_addr)),
        3 => return to_binary(&format!("cb_msg: {:?}", String::from_utf8(cbm_store.usr_cb_msg.as_slice().to_vec()))),
        4 => return to_binary(&format!("cb_msg index: {:}", idx)),
        5 => return to_binary(&format!("forward entropy?: {:}", entrp_chk.forw_entropy_check)),
        6 => return to_binary(&format!("forward entropy hash: {:}", config.forw_entropy_to_hash)),
        7 => return to_binary(&format!("forward entropy addr: {:}", config.forw_entropy_to_addr)),
        8 => return to_binary(&format!("admin address: {:?}", admin_human)),
        _ => return Err(StdError::generic_err("invalid number. Try 0-8"))
    };

    // to_binary(&QueryAnswer::Seed{seed: state.seed})

// /////////////////////////////////////////////////////////// 

    // to_binary(&QueryAnswer::RnOutput{rn: [0; 32]})
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
    let seed: Seed = load_state(&deps.storage, SEED_KEY)?; // remove `mut`

    // Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}", seed.seed, entropy);
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
