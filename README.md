# SECRET ORACLE - RNG 


## Project description
Secret Oracle - RNG (or Scrt-RNG) is a decentralized source of private randomness on Secret Network. It operates fully on-chain and requires only gas fees to use. It offers a solution to private randomness which is more secure than previous solutions on Secret Network.

## What Scrt-RNG offers
* Private randomness: random number outputs produced on transparent blockchains are recorded on-chain and publicly viewable for as long as the blockchain exists. This transparency limits possible use. Scrt-RNG transmits encrypted random numbers which are only viewable to the user.
* Secure: On-chain randomness has previously been possible on Secret Network, but existing implementations are typically exposed to various attack vectors that limit either the types of application, or the size of stakes before it becomes economically feasible for attackers to manipulate the RNG. Scrt-RNG aims to increase the cost and complexity of attacks, so higher-stakes applications can be deployed on Secret Network.
* No service fee: Scrt-RNG does not use no oracle nodes or incentivization tokens. As a result, the only fee that users pay for random numbers is the gas fee.
* Decentralized: Scrt-RNG has been deployed as a smart contract. The core algorithm is immutable and available to anyone with a Secret address (and later on, to the wider Cosmos ecosystem through contract-to-contract interactions through IBC). 

## Design
Scrt-RNG has two main generators that share the same entropy pool: a one-transaction model and a (more secure) two-transaction model

**One-transaction model:**
![1-transaction model](1-transaction-flowchart.png)

**Two-transaction model:**
![2-transaction model](2-transaction-flowchart.png)

## Example usage
The testnet has an instance of the random number generator ("Scrt-RNG") and a mock user contract ("rn-user"). As Scrt-RNG is designed for contract-to-contract interactions,  rn-user is helpful for developers as a ready-made user contract for developers to test with, and acts as a template with all the relevant functions required to interact with Scrt-RNG. 

Testnet (pulsar-2) contract instances:
```
# Scrt-RNG:
"address": "secret14yqa7fux3308kknsmdft8azmkje5krzwz570q9",
"label": "scrt-rng"
"Data hash": "15D8766782EE5434510FBA567E8376A7E39155B16D1CA2308FD2D8BB28AFB05C"

# mock user contract:
"address": "secret1ljgfvsertd9a6csn8rzvmneqgdu8kl9at5lw0w",
"label": "rn-user"
"Data hash": "CDA33FA3EBF5AB3F85787DA782F79E380FA700ECA5AD5833380435CB90BFB87A"
```

Mainnet (secret-4) contract instance:
```
"address": "secret12qeqaq5s4600j0wy4jmmjwgd693zhkj9f76r4l",
"label": "scrt-rng"
"Data hash": "2F1C1F1E2D9E55A1E75F1CB4F0E41D102242BA1AABB2449C9ED562AAEFB4E662"
```

### Sandbox RNG
The sandbox RNG gives developers a simple way to interact with Scrt-RNG through secretcli as a way to test its functionality. It draws and contributes to the same entropy pool with every interaction. However, it does not support contract-to-contract interaction, so it isn't intended for production use. It replies to the caller with a 256-bit random number (in a [u8; 32] array) via the `HandleResponse::data` field. Hence, contracts cannot use it. 

Example use using testnet address:
```
CONTRACT=secret14yqa7fux3308kknsmdft8azmkje5krzwz570q9; 
secretcli tx compute execute $CONTRACT '{"request_rn":{"entropy":"any string"}}' --from <account alias>
```
You can view the generated [u8; 32] random number with:
```
secretcli q compute tx <tx hash>
```
where `tx hash` is the transaction hash of the first transaction.

### 2-transaction RNG
This is Scrt-RNG's main random number generator. It is designed to have significantly higher security (ie: complexity and cost of attack vectors) than previously available solutions on Secret Network. A user contract makes two transactions:
- `create_rn` creates a random number which is stored in Scrt-RNG's contract storage. This is the point where the random number is determined, so users need to commit their stakes here. For example, a betting application needs to require their users to stake their betting amount along with the `create_rn` transaction.
- `fulfill_rn` which retrieves the random number that had been determined from the `create_rn` transaction. `fulfill_rn` needs to be called at least 1 block later.

Example use using pulsar-2 testnet address, calling Scrt-RNG using the mock user contract
```
CONTRACT=secret14yqa7fux3308kknsmdft8azmkje5krzwz570q9
HASH=15D8766782EE5434510FBA567E8376A7E39155B16D1CA2308FD2D8BB28AFB05C
USER=secret1ljgfvsertd9a6csn8rzvmneqgdu8kl9at5lw0w
USER_H=CDA33FA3EBF5AB3F85787DA782F79E380FA700ECA5AD5833380435CB90BFB87A
cb_msg='<any message here that the user contract needs in order to continue its execution after receiving the random number. Can be a struct with the relevant variables. The mock user contract is designed to take a String input>'
cb_msg0="$(base64 <<< $cb_msg0_msg)"

secretcli tx compute execute $USER '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>

secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$USER"'","receiver_code_hash":"'"$USER_H"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>
````
The mock user contract will create a log that prints `cb_msg: String` and the random number, which can be viewed with:
```
secretcli q compute tx <tx hash>
```   

There are optional inputs avaiable with `create_rn`:
* `purpose: String` allows USER contract to specify a unique identifier when creating an RN. An example is "user 1, round 3, item 2". This allows USER contract to control the flow of random numbers, and create multiple random numbers specific to different users and purposes.
* `receiver_addr: String` is the `HumanAddr` of the contract that will call `fulfill_rn`. If value is `None`, `creator` address = `receiver` address. This feature allows applications with multiple contracts to operate more easily. For example, `user contract 1` can create RN while `user contract 2` fulfills it. 
* `max_blk_delay` allows the user to specify the maximum number of blocks after `create_rn` before `fulfill_rn` must be called. The created RN will expire after the maximum block delay, allowing applications to set a time limit if required. If value is `None` then the max block delay defaults to 2^32 = 4,294,967,296 blocks, which effectively means the random number does not expire.

Note that at any point, only 1 random number can be created with any given combination of (creator, receiver, purpose). If multiple `create_rn`s are called with the same combination, the latest is used when `fulfill_rn` is called.

Example usage with all optional fields:
```
PURPOSE="roll dice"

secretcli tx compute execute $USER '{"trigger_create_rn":{"entropy":"any string", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":500,"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>

secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$USER"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>
```


### 1-transaction RNG
This is the basic RNG where a contract can call Scrt-RNG and receive a 256-bit random number in a single transaction. This is designed for applications which are able to sacrifice some security for greater ease-of-use. 1-transaction models were the only solution on the network prior to Scrt-RNG's launch, despite being vulnerable to certain attack vectors. Application developers should be aware of this if using this 1-transaction RNG. If appropriate for the application's use case, this RNG offers a simpler interface for applications, while drawing from the same entropy pool. 

```
callbackmsg='message before RN'
callbackbinary="$(base64 <<< $callbackmsg)" 

secretcli tx compute execute $USER '{"call_rn":{"entropy":"any string","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>

secretcli tx compute execute $USER '{"call_rn":{"entropy":"any string","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from <account alias>
```
As before, the mock user contract creates a log of the `callbackmsg` and random number:
```
secretcli q compute tx <tx hash> 
```

## More information
[scrt.network blog post](https://scrt.network/blog/secret-feature-secret-oracles)

[Medium article: introducing Scrt-RNG](https://medium.com/@DDT5/introducing-secret-oracle-rng-a4d15e06dcf6)

[Medium article: under the hood](https://medium.com/@DDT5/secret-oracle-rng-under-the-hood-e14a505ded0a)

## Licence
Apache License Version 2.0, January 2004
