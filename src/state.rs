use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use cosmwasm_std::{ReadonlyStorage, StdError, StdResult, Storage, CanonicalAddr, Binary};
use std::any::type_name;
use std::convert::TryInto;
use secret_toolkit::serialization::{Bincode2, Serde};
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};  // ReadonlySingleton, Singleton, singleton, singleton_read
use crate::{viewing_key::ViewingKey}; 

pub const SEED_KEY: &[u8] = b"seed";
pub const PRNG_KEY: &[u8] = b"prng";
pub static IDX_KEY0: &[u8] = b"index0"; // option 0
pub static IDX_KEY1: &[u8] = b"index1"; // option 1
pub static IDX_KEY2A: &[u8] = b"index2a"; // option 2a
pub static IDX_KEY2B: &[u8] = b"index2b"; // option 2b
pub const RN_STOR_KEY: &[u8] = b"rnstorage";
pub const ENTRP_CHK_KEY: &[u8] = b"entropycheck";
pub const FW_CONFIG_KEY: &[u8] = b"config"; // forward entropy config 
pub const ADMIN_KEY: &[u8] = b"admin";
pub const PREFIX_VIEWING_KEY: &[u8] = b"viewingkey";
pub const PERMITTED_VK: &[u8] = b"permittedvk"; // other contracts within the protocol (eg: scrt-rng2) can generate viewing keys
pub const VK_LOG: &[u8] = b"vklog"; // for transparency so anyone can see who has generated VK before (should only be other scrt-rng contracts)

/// RNG seed
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Seed {
    pub seed: [u8; 32],
}

/// viewing key seed
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PrngSeed {
    pub prng_seed: Vec<u8>,  
}

/// switch to determine if entropy is forwarded or not
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct EntrpChk {
    pub forw_entropy_check: bool,
}

/// config on which addresses to forward entropy to
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ForwEntrpConfig {
    pub forw_entropy_to_hash: Vec<String>,
    pub forw_entropy_to_addr: Vec<String>,
}

/// struct to hold addresses, used by several config settings
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AuthAddrs {
    pub addrs: Vec<CanonicalAddr>,
}

/// the key in the key-value pair for Option2
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct RnStorKy {
    pub creator_addr: CanonicalAddr,
    pub receiver_code_hash: String,
    pub receiver_addr: CanonicalAddr,
    pub purpose: Option<String>,
}

/// the value in the key-value pair for Option2
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema, Default)]
pub struct RnStorVl {
    pub usr_rn: [u8; 32],
    pub usr_cb_msg: Binary,
    pub blk_height: u64,
    pub max_blk_delay: u64,
}

// rn storage for "Option 2"
pub fn write_rn_store<S: Storage>(store: &mut S, key: &RnStorKy, value: &RnStorVl) -> StdResult<()> {
    let mut usr_rn_store = PrefixedStorage::new(RN_STOR_KEY, store);
    let mut usr_rn_store = TypedStoreMut::attach(&mut usr_rn_store);
    let key_vec = &Bincode2::serialize(key)?; 
    let key_bin: &[u8] = key_vec.as_slice().try_into().expect("cannot convert storage key into binary"); 
    usr_rn_store.store(key_bin, value)
}

pub fn read_rn_store<S: Storage>(store: &S, key: &RnStorKy) -> StdResult<Option<RnStorVl>> {
    let usr_rn_store = ReadonlyPrefixedStorage::new(RN_STOR_KEY, store);
    let usr_rn_store = TypedStore::attach(&usr_rn_store);
    let key_vec = &Bincode2::serialize(key)?; 
    let key_bin: &[u8] = key_vec.as_slice().try_into().expect("cannot convert storage key into binary"); 
    let usr_msg = usr_rn_store.may_load(key_bin);
    usr_msg
    // usr_msg.map(Option::unwrap_or_default)
}

pub fn remove_rn_store<S: Storage>(store: &mut S, key: &RnStorKy) -> StdResult<()> {
    let mut usr_rn_store = PrefixedStorage::new(RN_STOR_KEY, store);
    let mut usr_rn_store: TypedStoreMut<RnStorVl, PrefixedStorage<S>> = TypedStoreMut::attach(&mut usr_rn_store);
    let key_vec = &Bincode2::serialize(key)?; 
    let key_bin: &[u8] = key_vec.as_slice().try_into().expect("cannot convert storage key into binary"); 
    Ok(usr_rn_store.remove(key_bin))
}

// Viewing key for authenticated queries
pub fn write_viewing_key<S: Storage>(store: &mut S, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut user_key_store = PrefixedStorage::new(PREFIX_VIEWING_KEY, store);
    user_key_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let user_key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEWING_KEY, store);
    user_key_store.get(owner.as_slice())
}

// State for various storage structs
pub fn load_state<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Bincode2::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

pub fn save_state<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}
