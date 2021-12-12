use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use cosmwasm_std::{ReadonlyStorage, StdError, StdResult, Storage, CanonicalAddr};
use std::any::type_name;
use secret_toolkit::serialization::{Bincode2, Serde};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use crate::viewing_key::ViewingKey;

pub static CONFIG_KEY: &[u8] = b"config";
pub const PREFIX_VIEWING_KEY: &[u8] = b"viewingkey";

pub fn write_viewing_key<S: Storage>(store: &mut S, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut user_key_store = PrefixedStorage::new(PREFIX_VIEWING_KEY, store);
    user_key_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let user_key_store = ReadonlyPrefixedStorage::new(PREFIX_VIEWING_KEY, store);
    user_key_store.get(owner.as_slice())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub seed: [u8; 32],
    pub prng_seed: Vec<u8>,  // viewing key seed
}

pub fn load_seed<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Bincode2::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

pub fn save_seed<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}
