#!/bin/bash

# ########################################################################
# create functions
# ########################################################################

# Just like `echo`, but prints to stderr
function log() {
    echo "$@" >&2
}
# suppress all output to stdout for the command described in the arguments
function quiet() {
    "$@" >/dev/null
}
function tx_of() {
    "$@" | jq -r '.txhash'
}; \
function log_of() {
    "$@" | jq '.output_log[].attributes[1].value'
}; \
function data_of() {
    "$@" | jq -er '.output_data_as_string'
}; \
# function gas_of() {
#     "$@" | jq '.gas_used'
# }; \
function gas_of() {
    local txh="$1"
    local txt="$2"  # describe what the tx is
    local gas

    gas="$(secretcli q tx $txh | jq -r '.gas_used')"
    echo "$txt: $gas"
}; \
gas_log="$(echo "Gas used by" $'\n')"
function log_gas() {
    local txh="$1"
    local txt="$2"
    tx_gas="$(gas_of $txh $txt)"
    gas_log="$(echo "${gas_log}" $'\n'"${tx_gas}")"
    # log "$gas_log"
}
function balance_of() {
    "$@" | jq '.value.coins[].amount'
}; \

# Pad the string in the first argument to 256 bytes, using spaces
function pad_space() {
    printf '%-256s' "$1"
}

function assert_eq() {
    set -e
    local left="$1"
    local right="$2"
    local message

    if [[ "$left" != "$right" ]]; then
        if [ -z ${3+x} ]; then
            local lineno="${BASH_LINENO[0]}"
            message="assertion failed on line $lineno - both sides differ. left: ${left@Q}, right: ${right@Q}"
        else
            message="$3"
        fi
        log "$message"
        
        return 1
    fi
    log "assert_eq SUCCESS!"
    set +e
    return 0
}

function assert_ne() {
    set -e
    local left="$1"
    local right="$2"
    local message

    if [[ "$left" == "$right" ]]; then
        if [ -z ${3+x} ]; then
            local lineno="${BASH_LINENO[0]}"
            message="assertion failed on line $lineno - both sides are equal. left: ${left@Q}, right: ${right@Q}"
        else
            message="$3"
        fi

        log "$message"
        
        return 1
    fi
    log "assert_ne pass!"
    set +e
    return 0
}

# Keep polling the blockchain until the tx completes.
# The first argument is the tx hash.
# The second argument is a message that will be logged after every failed attempt.
# The tx information will be returned.
function wait_for_tx() {
    local tx_hash="$1"
    local message="$2"

    local result

    log "waiting for tx: $tx_hash"
    # secretcli will only print to stdout when it succeeds
    until result="$(secretcli query tx "$tx_hash" 2>/dev/null)"; do
        log "$message"
        sleep 2
    done

    # log out-of-gas events
    if quiet jq -e '.raw_log | startswith("execute contract failed: Out of gas: ") or startswith("out of gas:")' <<<"$result"; then
        log "$(jq -r '.raw_log' <<<"$result")"
    fi

    echo "$result"
}

# This is a wrapper around `wait_for_tx` that also decrypts the response,
# and returns a nonzero status code if the tx failed
function wait_for_compute_tx() {
    local tx_hash="$1"
    local message="$2"
    local return_value=0
    local result
    local decrypted

    result="$(wait_for_tx "$tx_hash" "$message")"
    # log "$result"
    if quiet jq -e '.logs == null' <<<"$result"; then
        return_value=1
    fi
    decrypted="$(secretcli query compute tx "$tx_hash")" || return
    log "$decrypted"
    echo "$decrypted"

    return "$return_value"
}
function quiet_wait_for_compute_tx() {
    local tx_hash="$1"
    local message="$2"
    local return_value=0
    local result
    local decrypted

    result="$(wait_for_tx "$tx_hash" "$message")"
    # log "$result"
    if quiet jq -e '.logs == null' <<<"$result"; then
        return_value=1
    fi
    decrypted="$(secretcli query compute tx "$tx_hash")" || return
    # log "$decrypted"
    # echo "$decrypted"

    return "$return_value"
}

# ########################################################################
# Instantiate contracts
# ########################################################################

# upload all three contracts at once 
secretcli tx compute store rng.wasm.gz --from a --gas 4000000 -y;
secretcli tx compute store interface.wasm.gz --from b --gas 4000000 -y; 
secretcli tx compute store user.wasm.gz --from c --gas 4000000 -y; 
txh="$(tx_of secretcli tx compute store rng.wasm.gz --from d --gas 4000000 -y)";
wait_for_tx $txh "waiting";
# upload another (third) scrt-rng and a second user
txh="$(tx_of secretcli tx compute store rng.wasm.gz --from a --gas 4000000 -y)";
txh="$(tx_of secretcli tx compute store user.wasm.gz --from b --gas 4000000 -y)";
wait_for_tx $txh "waiting";

# secretcli query compute list-code

INIT='{"initseed": "initseed input String","prng_seed":"seed string here"}'; 
CODE_ID=1 ;
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "my ORACLE!" -y)"
wait_for_compute_tx $txh "waiting";

# secretcli query compute list-contract-by-code 1

AA="$(secretcli keys show --address a)";  
BB="$(secretcli keys show --address b)";  
CC="$(secretcli keys show --address c)";  
CONTRACT="$(secretcli query compute list-contract-by-code 1 | jq -er '.[].address')";
HASH="$(secretcli q compute contract-hash $CONTRACT | sed 's/^0x//')";

# instantiate scrt-rng-interface 
INIT_CB_MSG="$(base64 <<<'init cb message')"; 
INIT='{"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'","init_cb_msg":"'"$INIT_CB_MSG"'","cb_offset":1}' 
CODE_ID=2 ; \
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "rng INTERFACE!" -y)"
wait_for_compute_tx $txh "waiting";

INTERF="$(secretcli query compute list-contract-by-code 2 | jq -er '.[].address')";
INTERF_H="$(secretcli q compute contract-hash $INTERF | sed 's/^0x//')";

# instantiate rn-user(s)
INIT='{"rng_addr":"'"$CONTRACT"'","rng_interf_addr":"'"$INTERF"'"}' 
CODE_ID=3 ; \
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "rn USER!" -y)"

CODE_ID=6 ;
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from b --label "rn USER 2!" -y)"
wait_for_compute_tx $txh "waiting";

USER="$(secretcli query compute list-contract-by-code 3 | jq -er '.[].address')";
USER_H="$(secretcli q compute contract-hash $USER | sed 's/^0x//')";

USER2="$(secretcli query compute list-contract-by-code $CODE_ID | jq -er '.[].address')";
USER2_H="$(secretcli q compute contract-hash $USER2 | sed 's/^0x//')";

# instantiate second and third rn-user 
INIT='{"initseed": "initseed input String", "prng_seed":"seed string here"}'
CODE_ID=4 ;
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from a --label "my SECOND oracle!" -y)"

CODE_ID=5 ;
txh="$(tx_of secretcli tx compute instantiate $CODE_ID "$INIT" --from b --label "my THIRD oracle!" -y)"
wait_for_compute_tx $txh "waiting";

CONTRACT2="$(secretcli query compute list-contract-by-code 4 | jq -er '.[].address')";
HASH2="$(secretcli q compute contract-hash $CONTRACT2 | sed 's/^0x//')";
CONTRACT3="$(secretcli query compute list-contract-by-code 5 | jq -er '.[].address')";
HASH3="$(secretcli q compute contract-hash $CONTRACT3 | sed 's/^0x//')";

# ########################################################################
# test functions
# ########################################################################

# ------------------------------------------------------------------------
# Option 1 functions
# ------------------------------------------------------------------------
function test_op1() {
    callbackbinary="$(base64 <<<'message before RN')"

    # two consecutive callback_rn results in different RN (ie: changes seed)
    txh0="$(tx_of secretcli tx compute execute $CONTRACT '{"callback_rn": {"entropy":"foo bar","cb_msg":"'"$callbackbinary"'", "callback_code_hash":"'"$HASH"'", "contract_addr":"'"$CONTRACT"'"}}' --amount "100000uscrt" --gas 250000 --from a -y)";
    txh1="$(tx_of secretcli tx compute execute $CONTRACT '{"callback_rn": {"entropy":"foo bar","cb_msg":"'"$callbackbinary"'", "callback_code_hash":"'"$HASH"'", "contract_addr":"'"$CONTRACT"'"}}' --amount "100000uscrt" --gas 250000 --from b -y)";
    wait_for_compute_tx $txh1 "waiting for tx"
    RN0="$(secretcli q compute tx $txh0 | jq '.output_log[].attributes[1].value')"
    RN1="$(secretcli q compute tx $txh1 | jq '.output_log[].attributes[1].value')"
    echo "testing: consecutive callback_rn has different RN: $RN0 vs $RN1"
    assert_ne $RN0 $RN1
    echo "testing: RN non-empty"
    assert_ne $RN0 ""; assert_ne $RN1 ""
    log_gas $txh0 "callback_rn-through-cli"

    # User contract can callback_rn and receive cb_msg, and RN (seed) changes
    callbackmsg='message before RN from user'
    callbackbinary="$(base64 <<< $callbackmsg)" 
    txh0="$(tx_of secretcli tx compute execute $USER '{"call_rn":{"entropy":"foo bar","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --amount "200000uscrt" --from a --gas 300000 -y)"
    txh1="$(tx_of secretcli tx compute execute $USER '{"call_rn":{"entropy":"foo bar","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --amount "200000uscrt" --from b --gas 300000 -y)"
    wait_for_compute_tx $txh1 "waiting for tx"
    echo "testing: cb_msg should be: $callbackmsg"
    assert_eq "$(secretcli q compute tx $txh0 | jq -r '.output_log[].attributes[] | select(.key=="cb_msg") | .value')" "$callbackmsg"

    RN0="$(secretcli q compute tx $txh0 | jq -r '.output_log[].attributes[] | select(.key=="rn") | .value')"
    RN1="$(secretcli q compute tx $txh1 | jq -r '.output_log[].attributes[] | select(.key=="rn") | .value')"
    echo "testing: RN changed, when called by a contract twice: $RN0 vs $RN1"
    assert_ne $RN0 $RN1
    echo "testing: RN non-empty"
    assert_ne $RN0 ""; assert_ne $RN1 ""
    log_gas $txh0 "callback_rn-via-rn_user-contract"
}

# ------------------------------------------------------------------------
# Option 2 functions
# ------------------------------------------------------------------------
function test_op2() {
    cb_msg0_msg='message from user0'
    cb_msg0="$(base64 <<< $cb_msg0_msg)";
    PURPOSE="roll dice"

    # create_rn and fulfill_rn
    txh0="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    txh1="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":2}}' --from b --gas 300000 -y)"
    txh2="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":2}}' --from c --gas 300000 -y)"
    wait_for_compute_tx $txh2 "waiting for tx";

    txh3="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from c --gas 300000 -y)"
    txh4="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$BB"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from d --gas 300000 -y)"
    wait_for_compute_tx $txh4 "waiting for tx";
    seed0="$(secretcli q compute query $CONTRACT '{"query_config": {"what":0}}')"
    
    txh5="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$CC"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh5 "waiting for tx"
    seed1="$(secretcli q compute query $CONTRACT '{"query_config": {"what":0}}')"
    
    echo "testing: create_rn and fulfill_rn"
    assert_ne "$(secretcli q compute tx $txh3 | jq '.output_log[]')" ""
    # assert_eq "$(secretcli q compute tx $txh2 | jq '.output_error[]')" "" 

    RN0="$(secretcli q compute tx $txh3 | jq -r '.output_log[].attributes[] | select(.key=="rn") | .value')"
    RN1="$(secretcli q compute tx $txh4 | jq -r '.output_log[].attributes[] | select(.key=="rn") | .value')"
    echo "testing: consecutive create_rn has different RN: $RN0 vs $RN1"
    assert_ne $RN0 $RN1
    echo "testing: RN non-empty"
    assert_ne $RN0 ""; assert_ne $RN1 ""

    echo "testing: fulfill_rn received correct cb_msg: $cb_msg0_msg"
    assert_eq "$(secretcli q compute tx $txh3 | jq -r '.output_log[].attributes[] | select(.key=="cb_msg") | .value')" "$cb_msg0_msg"

    echo "testing: fulfill_rn received correct purpose: $PURPOSE"
    assert_eq "$(secretcli q compute tx $txh3 | jq -r '.output_log[].attributes[] | select(.key=="purpose") | .value')" "Some(\"$PURPOSE\")"

    echo "testing: contract fulfill_rn changes seed (needs debugging seed query to be active). $seed0 vs $seed1"
    assert_ne $seed0 $seed1 
    assert_ne $seed0 ""; assert_ne $seed1 ""
    
    log_gas $txh0 "create_rn-via-cli"
    log_gas $txh3 "fulfill_rn-via-rn_user"

    # User contract can create_rn and fulfill_rn
    txh0="$(tx_of secretcli tx compute execute $USER '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1,"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh0 "waiting"

    txh1="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$USER"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh1 "waiting"

    echo "testing: contract create_rn"
    assert_eq "$(secretcli q compute tx $txh0 | jq '.output_error[]')" "" 

    echo "testing: contract fulfill_rn: correct cb_msg: $cb_msg0_msg"
    assert_eq "$(secretcli q compute tx $txh1 | jq -r '.output_log[].attributes[] | select(.key=="cb_msg") | .value')" "$cb_msg0_msg" 

    echo "testing: contract fulfill_rn: correct purpose: $PURPOSE"
    assert_eq "$(secretcli q compute tx $txh1 | jq -r '.output_log[].attributes[] | select(.key=="purpose") | .value')" "Some(\"$PURPOSE\")" 

    # testing: create RN and fulfill RN in same block -> error
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: create RN and fulfill RN in same block -> error"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[].msg')" "\"please wait for a short time between creating rn and transmitting rn"\"

    # max block delay exceeded
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"request_rn": {"entropy":"foo bar"}}' --from a -y)"
    quiet_wait_for_compute_tx $txh "pausing..."
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: max block delay exceeded"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[].msg')" '"delay between create_rn and transmit_rn exceeds max delay specified by user"'

    # cannot fulfill_rn more than once
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: cannot fulfill_rn more than once -- first attempt should succeed"
    assert_ne "$(secretcli q compute tx $txh | jq '.output_log[]')" ""

    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: cannot fulfill_rn more than once"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "generic_err" 

    # fulfill_rn can only be called by receiver
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $USER2 '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: fulfill_rn can only be called by receiver"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "generic_err" 

    # fulfill_rn calls non-existent entry results in error: creator_addr
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$BB"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: wrong creator_addr"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "generic_err" 

    # fulfill_rn calls non-existent entry results in error: wrong receiver_hash
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx";
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$HASH"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: wrong receiver_hash"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "generic_err" 

    # fulfill_rn calls non-existent entry results in error: wrong purpose
    WRONG_PURPOSE="shuffle cards"
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx";
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$WRONG_PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: wrong purpose"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "generic_err" 
}

# Works when Option<T> inputs are None
# Todo!() 

# ------------------------------------------------------------------------
# Admin functions
# ------------------------------------------------------------------------

# Non-admin cannot access config function...

# ...or change_admin function

# Admin can add new admin

# New admin cannot remove creator

# Creator cannot remove creator

# New admin can change config

# Creator can change config

# New admin can remove itself as admin


# ------------------------------------------------------------------------
# Forward entropy functions
# ------------------------------------------------------------------------

# Admin to config forward entropy

# Forward entropy changes seed of Scrt-RNG 2

# Forward entropy -- print gas before and after

# Scrt-RNG 2 can query from Scrt-RNG 1 to benefit from entropy

# Gas impact of querying from Scrt-RNG 1 to get entropy

# ------------------------------------------------------------------------
# Authenticated query checks
# ------------------------------------------------------------------------

# Non authenticated contract cannot generate VK

# Non-admin cannot add auth contract

# Admin can add auth contract

# Authenticated contract can generate VK

# Authenticated contract can auth_query to get RN

# Non authenticated contract cannot auth_query to get RN (wrong address or VK)

# query_config works? (for transparency)

# ------------------------------------------------------------------------
# Cross chain interface
# ------------------------------------------------------------------------

# Todo!()



# ########################################################################
# Execute tests
# ########################################################################
test_op1
test_op2
# Print gas usage
echo "$gas_log"
