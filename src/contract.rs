use schemars::JsonSchema;
// use serde::__private::de::IdentifierDeserializer;
// use schemars::_serde_json::Serializer;
use serde::{Deserialize, Serialize};  

use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier, debug_print,
    StdError, StdResult, QueryResult, 
    Storage, BankMsg, Coin, CosmosMsg, Uint128,
    HumanAddr, log, CanonicalAddr, //CanonicalAddr
};

use crate::msg::{InitMsg, HandleMsg, HandleAnswer, QueryMsg, QueryAnswer}; //self
use crate::state::{
    Seed, EntrpChk, AuthAddrs, ForwEntrpConfig, PrngSeed, RnStorKy, RnStorVl,
    load_state, save_state, write_viewing_key, read_viewing_key, idx_read, idx_write, write_rn_store, read_rn_store, remove_rn_store,
    SEED_KEY, FW_CONFIG_KEY, ADMIN_KEY, ENTRP_CHK_KEY, PRNG_KEY, PERMITTED_VK, VK_LOG,
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
pub const MIN_FEE: Uint128 = Uint128(0); /* 1mn uscrt = 1 SCRT */

/////////////////////////////////////////////////////////////////////////////////
// Enums for callback
/////////////////////////////////////////////////////////////////////////////////


// Calling receive_rn handle in user's contract ("Option 1")
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveRnHandleMsg {
    ReceiveRn {rn: [u8; 32], cb_msg: Binary},
}

impl HandleCallback for ReceiveRnHandleMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

// Calling receive_transmit_rn handle in receiver's contract ("Option 2")
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveFRnHandleMsg {
    ReceiveFRn {rn: [u8; 32], cb_msg: Binary, purpose: Option<String>},
}

impl HandleCallback for ReceiveFRnHandleMsg {
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
    let admin = AuthAddrs {
        addrs: vec![deps.api.canonical_address(&env.message.sender)?],
    };
    save_state(&mut deps.storage, ADMIN_KEY, &admin)?;

    let entrp_chk = EntrpChk {
        forw_entropy_check: false,
    };
    save_state(&mut deps.storage, ENTRP_CHK_KEY, &entrp_chk)?;

    let config = ForwEntrpConfig {
        forw_entropy_to_hash: vec![String::default()],
        forw_entropy_to_addr: vec![String::default()],
    };
    save_state(&mut deps.storage, FW_CONFIG_KEY, &config)?;

    let pseed = PrngSeed {
        prng_seed: sha_256(base64::encode(msg.prng_seed).as_bytes()).to_vec(),
    };
    save_state(&mut deps.storage, PRNG_KEY, &pseed)?;

    // initialize PERMITTED_VK and VK_LOG to vec![]
    let empty_vec: Vec<HumanAddr> = vec![];
    save_state(&mut deps.storage, PERMITTED_VK, &empty_vec)?;
    save_state(&mut deps.storage, VK_LOG, &empty_vec)?;

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
        HandleMsg::ConfigureFwd {
            forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr,
        } => try_configure_fwd(deps, env, forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr),
        HandleMsg::ConfigureAuth {add} => try_configure_auth(deps, env, add),
        HandleMsg::AddAdmin {add} => try_add_admin(deps, env, add),
        HandleMsg::RemoveAdmin {remove} => try_remove_admin(deps, env, remove),

        HandleMsg::DonateEntropy {entropy} => donate_entropy(deps, env, entropy),
        HandleMsg::DonateEntropyRwrd {entropy} => donate_entropy_rwrd(deps, env, entropy),

        HandleMsg::RequestRn {entropy} => try_request_rn(deps, env, entropy),

        HandleMsg::CallbackRn {
            entropy, cb_msg, callback_code_hash, contract_addr
        } => try_callback_rn(deps, env, entropy, cb_msg, callback_code_hash, contract_addr),

        HandleMsg::CreateRn {
            entropy, cb_msg, receiver_code_hash, receiver_addr, purpose, max_blk_delay
        } => try_create_rn(deps, env, entropy, cb_msg, receiver_code_hash, receiver_addr, purpose, max_blk_delay),

        HandleMsg::FulfillRn {
            creator_addr, receiver_code_hash, purpose
        } => try_fulfill_rn(deps, env, creator_addr, receiver_code_hash, purpose),

        HandleMsg::ReceiveRn {
            rn, cb_msg
        } => try_receive_rn(deps, env, rn, cb_msg),

        HandleMsg::GenerateViewingKey {entropy, .. } => try_generate_viewing_key(deps, env, entropy),
    };
    pad_handle_result(response, BLOCK_SIZE)
}

fn try_configure_fwd<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    forw_entropy: bool,
    forw_entropy_to_hash: Vec<String>,
    forw_entropy_to_addr: Vec<String>,
) -> StdResult<HandleResponse> {
    // check if admin
    let admins_vec: AuthAddrs = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_auth(deps, &env, &admins_vec)?;

    // change Forward Entropy Config
    let new_entrp_chk = EntrpChk {
        forw_entropy_check: forw_entropy
    };
    let new_config = ForwEntrpConfig {
        forw_entropy_to_hash: forw_entropy_to_hash,
        forw_entropy_to_addr: forw_entropy_to_addr,
    };
    save_state(&mut deps.storage, ENTRP_CHK_KEY, &new_entrp_chk)?;
    save_state(&mut deps.storage, FW_CONFIG_KEY, &new_config)?;
    
    Ok(HandleResponse::default())
}

/// Add authenticated address to access query_rn (other scrt-rng contracts)
/// for transparency/security, addresses can only be added (and not removed)
/// so anyone can query_config to see all addrs that had been able to generate VK
fn try_configure_auth<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    add: String,
) -> StdResult<HandleResponse> {
    // check if admin
    let admins_vec: AuthAddrs = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_auth(deps, &env, &admins_vec)?;

    // add auth
    let mut auth_vec: AuthAddrs = load_state(&mut deps.storage, PERMITTED_VK)?;    
    auth_vec.addrs.extend(deps.api.canonical_address(&HumanAddr(add)));
    save_state(&mut deps.storage, PERMITTED_VK, &auth_vec.addrs)?;

    Ok(HandleResponse::default())
}

fn try_add_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    add: String,
) -> StdResult<HandleResponse> {
    // check if admin
    let mut admins_vec: AuthAddrs = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_auth(deps, &env, &admins_vec)?;
    
    // add admin
    admins_vec.addrs.extend(deps.api.canonical_address(&HumanAddr(add)));
    save_state(&mut deps.storage, ADMIN_KEY, &admins_vec.addrs)?;

    Ok(HandleResponse::default())
}

fn try_remove_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    remove: String,
) -> StdResult<HandleResponse> {
    // check if admin
    let mut admins_vec: AuthAddrs = load_state(&mut deps.storage, ADMIN_KEY)?;
    check_auth(deps, &env, &admins_vec)?;

    // cannot remove creator
    let remove_canon = deps.api.canonical_address(&HumanAddr(remove))?;
    if remove_canon == admins_vec.addrs[0] {
        return Err(StdError::generic_err(
            "Cannot remove creator as admin"
        ));
    }

    // remove admin
    admins_vec.addrs.retain(|x| x != &remove_canon);
    save_state(&mut deps.storage, ADMIN_KEY, &admins_vec.addrs)?;

    Ok(HandleResponse::default())
}

fn check_auth<S: Storage, A: Api, Q:Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    addr_vec: &AuthAddrs, 
) -> StdResult<()> {
    let addrs = &addr_vec.addrs;
    let sender = &deps.api.canonical_address(&env.message.sender)?;
    if !addrs.contains(&sender) {
        return Err(StdError::generic_err(
            "This is an authenticated function",
        ));
    }
    Ok(())
}

fn change_seed<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: T,
) -> StdResult<[u8; 32]> {
    debug_print!("change_seed: initiated");
    //Load state (seed)
    let mut seed: Seed = load_state(&deps.storage, SEED_KEY)?;
    debug_print!("change_seed: old seed loaded");

    //Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", entropy, seed.seed, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("failed to create new seed");
    debug_print!("change_seed: new seed created");

    //Save Seed
    seed.seed = new_seed;
    save_state(&mut deps.storage, SEED_KEY, &seed)?;
    debug_print!("change_seed: new seed saved");

    Ok(new_seed)
}


fn get_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    entropy: T
) -> StdResult<[u8; 32]> { 
    debug_print!("get_rn: initiated");

    let new_seed = change_seed(deps, env, entropy)?;

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
) -> StdResult<Option<Vec<CosmosMsg>>> {
    debug_print!("forward entropy: initiated");
    let entrp_chk: EntrpChk = load_state(&deps.storage, ENTRP_CHK_KEY)?;
    debug_print!("forward entropy: marker 2");

    if entrp_chk.forw_entropy_check == true {
        debug_print!("forward entropy: marker 3");
        let config: ForwEntrpConfig = load_state(&deps.storage, FW_CONFIG_KEY)?;
        let entropy_hashed_full = &sha2::Sha256::digest(format!("{:?}", &entropy).as_bytes());
        // forward a String of the first 32 bits; saves a bit of gas vs sending the whole 256bit String:
        let entropy_hashed = &entropy_hashed_full.as_slice()[0..4]; 
        let donate_entropy_msg = DonateEntropyMsg::DonateEntropy {
            entropy: format!("{:?}", &entropy_hashed),
        };
        debug_print!("entropy String forwarded: {:?}", entropy_hashed);
        
        let mut cosmos_msgs = vec![];
        for i in 0..config.forw_entropy_to_hash.len() {
            cosmos_msgs.push(
                donate_entropy_msg.to_cosmos_msg(
                config.forw_entropy_to_hash[i].to_string(), 
                HumanAddr(config.forw_entropy_to_addr[i].to_string()), 
                None
                )?
            );
        }
        Ok(Some(cosmos_msgs))
    }
    else {
        debug_print!("forward entropy: marker 4");
        Ok(None)
    }
}


pub fn try_generate_viewing_key<S: Storage, A: Api, Q: Querier> (
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String
) -> StdResult<HandleResponse> {
    // Only other scrt-rng protocol contracts can generate VK
    let auth_vec: AuthAddrs = load_state(&mut deps.storage, PERMITTED_VK)?;
    check_auth(deps, &env, &auth_vec)?;

    // Generated VK
    let config: PrngSeed = load_state(&mut deps.storage, PRNG_KEY)?;   // changed this from CONFIG_KEY
    let prng_seed = config.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;

    write_viewing_key(&mut deps.storage, &message_sender, &key);

    // log addr that generated VK -- should only be other scrt-rng protocol contracts
    let mut vklog_vec: AuthAddrs = load_state(&mut deps.storage, VK_LOG)?;    
    vklog_vec.addrs.extend(deps.api.canonical_address(&env.message.sender));
    save_state(&mut deps.storage, VK_LOG, &vklog_vec.addrs)?;

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

pub fn try_request_rn<S:Storage, A:Api, Q:Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let rn_output = get_rn(deps, &env, &entropy)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Rn {
            rn: rn_output,
            })?)
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
    let rn_output = get_rn(deps, &env, &entropy)?;

    debug_print!("try_callback_rn: passed get_rn");

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
    let cosmos_msg_fwd_entropy = forward_entropy(deps, &env, &entropy)?;
    debug_print!("try_callback_rn: forward entropy done");

    // create multiple messages
    let mut messages = vec![cosmos_msg];
    match cosmos_msg_fwd_entropy {
        Some(mut i) => messages.append(&mut i),
        None => (),
    };

    let cb_resp_data = to_binary(&HandleAnswer::Rn {
        rn: rn_output,
    });

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        // data: None
        data: Some(cb_resp_data?), //FOR DEBUGGING --- REMOVE FOR FINAL IMPLEMENTATION
    })

    // Ok(HandleResponse::default())
}

/// Step 1 of "Option2". creates RN and potentially emits messages to forward entropy
pub fn try_create_rn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
    cb_msg: Binary,
    receiver_code_hash: String, 
    receiver_addr: Option<String>, 
    purpose: Option<String>,
    max_blk_delay: Option<u64>,
) -> StdResult<HandleResponse> {
    // create RN
    let rn_output = get_rn(deps, &env, &entropy)?;
    
    // store RN & related data
    let creator_addr = deps.api.canonical_address(&env.message.sender)?;
    let receiver_addr_result = match receiver_addr {
        Some(i) => deps.api.canonical_address(&HumanAddr(i))?,
        None => deps.api.canonical_address(&env.message.sender)?,
    };
    let key = RnStorKy {
        creator_addr: creator_addr,
        receiver_code_hash: receiver_code_hash.to_string(),
        receiver_addr: receiver_addr_result,
        purpose: purpose,
    };
    let value = RnStorVl {
        usr_rn: rn_output,
        usr_cb_msg: cb_msg,
        blk_height: env.block.height,
        max_blk_delay: max_blk_delay.unwrap_or_else(|| 2^32), // if no input, default max delay set at 2^32 blocks (effectively no max)
    };
    write_rn_store(&mut deps.storage, &key, &value)?;


    // add to count
    let idx = idx_read(&deps.storage).load()?;
    idx_write(&mut deps.storage).save(&(&idx+1))?;

    //Potentially forward entropy to another contract
    debug_print!("create_rn: forward entropy initiated");
    let cosmos_msg_fwd_entropy = forward_entropy(deps, &env, &entropy)?;
    debug_print!("create_rn: forward entropy done");
    let messages = cosmos_msg_fwd_entropy.unwrap_or_else(|| vec![]);
    debug_print!("create_rn: messages unwrapped");

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None
    })
}

/// Step 2 of "Option2". transmits RN
pub fn try_fulfill_rn<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    creator_addr: String,
    receiver_code_hash: String,
    purpose: Option<String>,
) -> StdResult<HandleResponse> {
    debug_print!("fulfill_rn: initiated");
    // change seed
    let entropy = format!("{:?} {:?}", &env.message, &purpose); 
    let _new_seed = change_seed(deps, &env, entropy)?;
    debug_print!("fulfill_rn: seed changed");

    // read from RN storage
    let key = RnStorKy {
        creator_addr: deps.api.canonical_address(&HumanAddr(creator_addr))?,
        receiver_code_hash: receiver_code_hash.to_string(),
        receiver_addr: deps.api.canonical_address(&env.message.sender)?, 
        purpose: purpose,
    };
    debug_print!("fulfill_rn: receiver_addr is: {:?}", deps.api.human_address(&key.receiver_addr));
    let usr_info_option = read_rn_store(&deps.storage, &key)?;
    debug_print!("fulfill_rn: usr_info retrieved from storage");

    // check if entry exists
    let usr_info = match usr_info_option {
        None => return Err(StdError::generic_err(
            "random number not found. Possible reasons (non-exhaustive): \n
            i) Random number not yet created -> Create random number using create_rn first. \n
            ii) Have been consumed -> random number can only be consumed once. Create new random number \n
            iii) fulfill_rn function must be called by the address that called create_rn, or the receiver_addr if specified as an
            input during create_rn -> ensure receiver is calling fulfill_rn \n
            iv) random numbers are stored using using a key-value pair, where the key is (creator, receiver_code_hash, purpose) -> ensure 
            combination matches what was input during create_rn  
            "
        )),
        Some(i) => i
    };
    debug_print!("fulfill_rn: usr_info verified to exist");

    // block height check
    let curr_height = env.block.height;
    if curr_height <= usr_info.blk_height + 0 { // at least min block delay (of 1)
        return Err(StdError::generic_err("please wait for a short time between creating rn and transmitting rn"));
    } else if curr_height > usr_info.blk_height + usr_info.max_blk_delay { // does not exceed max delay set by user
        return Err(StdError::generic_err("delay between create_rn and transmit_rn exceeds max delay specified by user"));
    };
    debug_print!("fulfill_rn: block height check done");

    // remove entry
    remove_rn_store(&mut deps.storage, &key)?;
    debug_print!("fulfill_rn: usr_info entry removed");

    // transmit msg: to receiver (to a receive_transmit_rn handle function)
    let receive_f_rn_msg = ReceiveFRnHandleMsg::ReceiveFRn {
        rn: usr_info.usr_rn,
        cb_msg: usr_info.usr_cb_msg,
        purpose: key.purpose,
    };

    let cosmos_msg = receive_f_rn_msg.to_cosmos_msg(
        key.receiver_code_hash.to_string(), 
        deps.api.human_address(&key.receiver_addr)?, 
        None
    )?;
    debug_print!("fulfill_rn: cosmos_msg created");

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![],
        data: None
    })
}


/// Function that user's receiving contract need to have. Here for testing purposes only
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



/////////////////////////////////////////////////////////////////////////////////
// Query functions 
/////////////////////////////////////////////////////////////////////////////////

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {  // StdResult<Binary> , QueryResult
    let response = match msg {
        // QueryMsg::QueryRn {entropy} => try_query_rn(deps, entropy),
        QueryMsg::QueryConfig {what} => try_query_config(deps, what), 
        _ => authenticated_queries(deps, msg),
   };
   pad_query_result(response, BLOCK_SIZE)
}

// pub fn try_query_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
//     deps: &Extern<S, A, Q>,
//     entropy: T,
// ) -> QueryResult {
//     // Load seed
//     let seed: Seed = load_state(&deps.storage, SEED_KEY)?; // remove `mut`

//     // Converts new entropy and old seed into a new seed
//     let new_string: String = format!("{:?}+{:?}", seed.seed, entropy);
//     let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
//     let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("Wrong length");
    
//     //Generate random number -- chacha
//     let mut rng = ChaChaRng::from_seed(new_seed);

//     let mut dest: Vec<u8> = vec![0; 32];  // bytes as usize];
//     for i in 0..dest.len() {
//         dest[i] = rng.gen();
//     }

//     let rn_output: [u8; 32] = dest.try_into().expect("cannot");

//     to_binary(&QueryAnswer::RnOutput{rn: rn_output})

// }


pub fn try_query_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    what: u32
) -> QueryResult {
    let seed: Seed = load_state(&deps.storage, SEED_KEY)?; 
    let idx: u32 = idx_read(&deps.storage).load()?;
    let admins: AuthAddrs = load_state(&deps.storage, ADMIN_KEY)?;
    let entrp_chk: EntrpChk = load_state(&deps.storage, ENTRP_CHK_KEY)?;
    let configfw: ForwEntrpConfig = load_state(&deps.storage, FW_CONFIG_KEY)?;
    let permittedvk: AuthAddrs = load_state(&deps.storage, PERMITTED_VK)?;
    let vklog: AuthAddrs = load_state(&deps.storage, VK_LOG)?;

    // Human Addrs
    let admin_human = humanize_vec(deps, admins.addrs)?;
    let permittedvk_human = humanize_vec(deps, permittedvk.addrs)?;
    let vklog_human = humanize_vec(deps, vklog.addrs)?;

    match what {
        0 => return to_binary(&format!("seed: {:?}", seed.seed)),  //FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION//////
        1 => return to_binary(&format!("created rns via option 2: {:}", idx)),  // <-- remove or make admin function 
        2 => return to_binary(&format!("forward entropy?: {:}", entrp_chk.forw_entropy_check)),
        3 => return to_binary(&format!("forward entropy hash: {:?}", configfw.forw_entropy_to_hash)),
        4 => return to_binary(&format!("forward entropy addr: {:?}", configfw.forw_entropy_to_addr)),
        5 => return to_binary(&format!("admin address: {:?}", admin_human)),
        6 => return to_binary(&format!("addresses that have been authenticated to generate VK: {:?}", permittedvk_human)),
        7 => return to_binary(&format!("address that have generated VK before: {:?}", vklog_human)),
        _ => return Err(StdError::generic_err("invalid number. Try 0-7"))
    };
}

fn humanize_vec<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    canon_addr_vec: Vec<CanonicalAddr>,
) -> StdResult<Vec<HumanAddr>> {
    let mut human_addr_vec: Vec<HumanAddr> = vec![];
    for addr in canon_addr_vec {
        human_addr_vec.push(deps.api.human_address(&addr)?)
    };

    Ok(human_addr_vec)
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

#[cfg(test)]
mod tests {
    // use std::fmt::Result;

    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coins, from_binary}; //, BlockInfo, ContractInfo, MessageInfo, QueryResponse, WasmMsg
    // use serde::__private::de::IdentifierDeserializer;

    #[test]
    fn callback_rn_changes_rn() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed string here")};
        let _res = init(&mut deps, env, msg).unwrap();

        let seed1: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };
        let env = mock_env("RN user", &coins(MIN_FEE.u128(), "uscrt"));
        let msg = HandleMsg::CallbackRn {entropy: String::from("foo bar"), cb_msg: Binary(String::from("cb_msg").as_bytes().to_vec()), callback_code_hash: "hash".to_string(), contract_addr: "addr".to_string()};

        let env1 = env.clone();
        let msg1 = msg.clone();
        let res1 = &handle(&mut deps, env1, msg1).unwrap().data;
        let seed2: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };

        let env2 = env.clone();
        let msg2 = msg.clone();
        let res2 = &handle(&mut deps, env2, msg2).unwrap().data;

        assert_eq!(seed1.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
        assert_ne!(seed2.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
        assert_ne!(res1, res2);
    }

    #[test]
    fn create_rn_changes_rn() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed string here")};
        let _res = init(&mut deps, env, msg).unwrap();

        let seed1: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };
        let env1 = mock_env("RN user", &[]);
        let msg1 = HandleMsg::CreateRn {
            entropy: "foo bar".to_string(), cb_msg: Binary(String::from("cb_msg").as_bytes().to_vec()), receiver_code_hash: "hash".to_string(), 
            receiver_addr: Some("receiver".to_string()), purpose: Some("roll dice".to_string()), max_blk_delay:Some(1)
        };
        let _res1 = &handle(&mut deps, env1, msg1).unwrap().data;

        let seed2: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };

        assert_eq!(seed1.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
        assert_ne!(seed2.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
    }

    #[test]
    fn donate_entropy_changes_seed() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed string here")};
        let _res = init(&mut deps, env, msg).unwrap();

        let seed1: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };
        let env = mock_env("RN user", &coins(0, "token"));
        let msg = HandleMsg::DonateEntropy {entropy: String::from("foo bar")};
        let _res = &handle(&mut deps, env, msg).unwrap().data;
        let seed2: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };

        assert_eq!(seed1.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
        assert_ne!(seed2.seed, [152, 161, 137, 248, 53, 129, 159, 79, 42, 186, 18, 209, 76, 173, 161, 91, 215, 133, 46, 162, 93, 212, 37, 67, 113, 10, 89, 255, 214, 195, 159, 14]);
    }

    #[test]
    fn admin_access_works() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed string here")};
        let _res = init(&mut deps, env, msg).unwrap();

        let msg0 = QueryMsg::QueryConfig {what: 2};
        let res0 = &query(&mut deps, msg0).unwrap();
        let env = mock_env("creator", &coins(0, "token"));
        let msg1 = HandleMsg::ConfigureFwd {forw_entropy: true, forw_entropy_to_hash: vec![String::from("hash")], forw_entropy_to_addr: vec![String::from("addr")]};
        let res1 = &handle(&mut deps, env, msg1);
        let msg2 = QueryMsg::QueryConfig {what: 2};
        let res2 = &query(&mut deps, msg2).unwrap();

        assert_eq!(from_binary::<String>(&res0).unwrap(), String::from("forward entropy?: false"));
        assert_eq!(res1.is_ok(), true);
        assert_eq!(from_binary::<String>(&res2).unwrap(), String::from("forward entropy?: true"));
    }

    #[test]
    fn admin_access_denied() {
        let mut deps = mock_dependencies(20, &coins(2, "token"));

        let env = mock_env("creator", &coins(2, "token"));
        let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed string here")};
        let _res = init(&mut deps, env, msg).unwrap();

        let msg0 = QueryMsg::QueryConfig {what: 2};
        let res0 = &query(&mut deps, msg0).unwrap();
        let env = mock_env("RN user", &coins(0, "token"));
        let msg1 = HandleMsg::ConfigureFwd {forw_entropy: true, forw_entropy_to_hash: vec![String::from("hash")], forw_entropy_to_addr: vec![String::from("addr")]};
        let res1 = &handle(&mut deps, env, msg1);
        let msg2 = QueryMsg::QueryConfig {what: 2};
        let res2 = &query(&mut deps, msg2).unwrap();

        assert_eq!(from_binary::<String>(&res0).unwrap(), String::from("forward entropy?: false"));
        // assert_eq!(res1.as_ref().err().unwrap(), &StdError::generic_err("This is an admin function"));
        assert!(res1.is_err());
        assert_eq!(res0, res2);
    }

    // #[test]
    // fn call_rn_requires_min_fee() {
    //     let mut deps = mock_dependencies(20, &coins(2, "token"));

    //     let env = mock_env("creator", &coins(2, "token"));
    //     let msg = InitMsg {initseed: String::from("initseed input String"), prng_seed: String::from("seed")};
    //     let _res = init(&mut deps, env, msg).unwrap();
        
    //     let env = mock_env("RN user", &coins(MIN_FEE.u128()-1, "uscrt"));
    //     let msg = HandleMsg::RnString {entropy: String::from("String input")};
    //     let res = call_rn(&mut deps, env, msg);

    //     match res {
    //         Err(StdError::GenericErr {..}) => {}
    //         _ => panic!("Should return inadequate fee error"),
    //     }
    // }
}
