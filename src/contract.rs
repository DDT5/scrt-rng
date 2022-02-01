use schemars::JsonSchema;
use serde::{Deserialize, Serialize};  

use cosmwasm_std::{
    to_binary, Api, Binary, Env, Extern, HandleResponse, InitResponse, Querier, debug_print,
    StdError, StdResult, QueryResult, 
    Storage, CosmosMsg, //Uint128,
    HumanAddr, log, CanonicalAddr,
};

use crate::msg::{InitMsg, HandleMsg, HandleAnswer, QueryMsg, QueryAnswer}; 
use crate::state::{
    Seed, EntrpChk, AuthAddrs, ForwEntrpConfig, PrngSeed, RnStorKy, RnStorVl,
    load_state, save_state, write_viewing_key, read_viewing_key, idx_read, idx_write, write_rn_store, read_rn_store, remove_rn_store,
    SEED_KEY, FW_CONFIG_KEY, ADMIN_KEY, ENTRP_CHK_KEY, PRNG_KEY, PERMITTED_VK, VK_LOG,
};  
use crate::viewing_key::{ViewingKey}; 
use crate::viewing_key::VIEWING_KEY_SIZE;

use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};  
use secret_toolkit::crypto::{sha_256};  

use rand_chacha::ChaChaRng;
use rand::{Rng, SeedableRng}; 
use sha2::{Digest};
use std::convert::TryInto;

pub const BLOCK_SIZE: usize = 256;

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

// Calling receive_f_rn handle in receiver's contract ("Option 2")
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



/////////////////////////////////////////////////////////////////////////////////
// Init function
/////////////////////////////////////////////////////////////////////////////////

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    // Init RNG seed 
    let init_seed_arr = sha2::Sha256::digest(msg.initseed.as_bytes());
    let init_seed: [u8; 32] = init_seed_arr.as_slice().try_into().expect("Invalid");
    let seed = Seed {
        seed: init_seed
    };
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

    // instantiator is the first admin
    let admin = AuthAddrs {
        addrs: vec![deps.api.canonical_address(&env.message.sender)?],
    };
    save_state(&mut deps.storage, ADMIN_KEY, &admin)?;

    // config on whether to forward entropy
    let entrp_chk = EntrpChk {
        forw_entropy_check: false,
    };
    save_state(&mut deps.storage, ENTRP_CHK_KEY, &entrp_chk)?;

    // config on which address to forward entropy to (a scrt-rng2 contract)
    let config = ForwEntrpConfig {
        forw_entropy_to_hash: vec![String::default()],
        forw_entropy_to_addr: vec![String::default()],
    };
    save_state(&mut deps.storage, FW_CONFIG_KEY, &config)?;

    // seed for viewing key
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

        HandleMsg::ConfigureFwd {
            forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr,
        } => try_configure_fwd(deps, env, forw_entropy, forw_entropy_to_hash, forw_entropy_to_addr),
        HandleMsg::ConfigureAuth {add} => try_configure_auth(deps, env, add),
        HandleMsg::GenerateViewingKey {entropy, receiver_code_hash, .. } => try_generate_viewing_key(deps, env, entropy, receiver_code_hash),

        HandleMsg::AddAdmin {add} => try_add_admin(deps, env, add),
        HandleMsg::RemoveAdmin {remove} => try_remove_admin(deps, env, remove),

        HandleMsg::DonateEntropy {entropy} => try_donate_entropy(deps, env, entropy),
    };
    pad_handle_result(response, BLOCK_SIZE)
}


// -------------------------------------------------------------------
// try functions, which are called directly by `handle` function
// -------------------------------------------------------------------

/// RNG responds with HandleResponse.data field. Limited use as contracts can't 
/// act on this response  
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

/// 1-transaction RNG, responds by sending message back to caller with a 
/// random number: [u8; 32] and cb_msg: Binary
/// Depending on config, potentially emits messages to forward entropy to 
/// another contract in the scrt-rng protocol 
pub fn try_callback_rn<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(   // 
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: T,
    cb_msg: Binary,
    callback_code_hash: String,
    contract_addr: String
) -> StdResult<HandleResponse> {
    debug_print!("try_callback_rn: initiated");

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

    Ok(HandleResponse {
        messages: messages,
        log: vec![],
        data: None
    })
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


/// Function that the receiving contract of the user needs to have. Here for testing purposes
pub fn try_receive_rn<S: Storage, A: Api, Q: Querier>(  
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

/// admins can specify if each interaction also forwards entropy to a
/// donate_entropy handle function on another contract. Used to share entropy
/// with a potential future scrt-rng contract 
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

/// Add authenticated address to access query_rn (other scrt-rng contracts). For
/// transparency/security, addresses can only be added (and not removed), so
/// anyone can query_config to see all addrs that had been able to generate VK
/// or have made txs to generate VKs before
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

pub fn try_generate_viewing_key<S: Storage, A: Api, Q: Querier> (
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
    receiver_code_hash: String,
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

    // create cosmos msg with viewing key
    let receive_vk_msg = HandleAnswer::ReceiveViewingKey {
        key: key,
    };

    let cosmos_msg = receive_vk_msg.to_cosmos_msg(
        receiver_code_hash.to_string(), 
        env.message.sender, 
        None
    )?;

    Ok(HandleResponse {
        messages: vec![cosmos_msg],
        log: vec![],
        data: None,
    })
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

/// Used to receive entropy from another contract. Allows other scrt-rng protocol 
/// contracts to share entropy. There is no incentive to do this, but anyone is 
/// free to add entropy to secure the contract if they are willing to bear the gas costs
pub fn try_donate_entropy<S: Storage, A: Api, Q: Querier, T:std::fmt::Debug>(
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


// -------------------------------------------------------------------
// additional functions to support handle messages
// -------------------------------------------------------------------

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
    //Load state (seed)
    let mut seed: Seed = load_state(&deps.storage, SEED_KEY)?;

    //Converts new entropy and old seed into a new seed
    let new_string: String = format!("{:?}+{:?}+{:?}", entropy, seed.seed, &env.block.time);
    let new_seed_arr = sha2::Sha256::digest(new_string.as_bytes());
    let new_seed: [u8; 32] = new_seed_arr.as_slice().try_into().expect("failed to create new seed");

    //Save Seed
    seed.seed = new_seed;
    save_state(&mut deps.storage, SEED_KEY, &seed)?;

    Ok(new_seed)
}

/// core RNG algorithm
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

    if entrp_chk.forw_entropy_check == true {
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
        Ok(None)
    }
}


/////////////////////////////////////////////////////////////////////////////////
// Query functions 
/////////////////////////////////////////////////////////////////////////////////

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {  // StdResult<Binary> , QueryResult
    let response = match msg {
        QueryMsg::QueryConfig {what} => try_query_config(deps, what), 
        _ => authenticated_queries(deps, msg),
   };
   pad_query_result(response, BLOCK_SIZE)
}

/// allows anyone to query the current configuration of the contract, the number of txs
/// calling create_rn (usage stats), and which addresses have generated viewing keys 
/// before (meant to be only for other scrt-rng contracts)
pub fn try_query_config<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    what: u32
) -> QueryResult {
    // let seed: Seed = load_state(&deps.storage, SEED_KEY)?; 
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
        // 0 => return to_binary(&format!("seed: {:?}", seed.seed)),  //FOR DEBUGGING --- MUST REMOVE FOR FINAL IMPLEMENTATION//////
        1 => return to_binary(&format!("created rns via option 2: {:}", idx)), 
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


// -------------------------------------------------------------------
// Authenticated Queries 
// -------------------------------------------------------------------

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
    use cosmwasm_std::{coins, from_binary}; 

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
        let env = mock_env("RN user", &coins(0, "uscrt"));
        let msg = HandleMsg::CallbackRn {entropy: String::from("foo bar"), cb_msg: Binary(String::from("cb_msg").as_bytes().to_vec()), callback_code_hash: "hash".to_string(), contract_addr: "addr".to_string()};

        let env1 = env.clone();
        let msg1 = msg.clone();
        let res1 = &handle(&mut deps, env1, msg1).unwrap().messages;
        let seed2: Seed = match load_state(&mut deps.storage, SEED_KEY) {
            Ok(i) => i,
            Err(_) => panic!("no seed loaded"),
        };

        let env2 = env.clone();
        let msg2 = msg.clone();
        let res2 = &handle(&mut deps, env2, msg2).unwrap().messages;

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
}
