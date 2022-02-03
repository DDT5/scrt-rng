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
secretcli tx compute store rng.wasm.gz --from b --gas 4000000 -y; 
txh="$(tx_of secretcli tx compute store rng.wasm.gz --from c --gas 4000000 -y)";
wait_for_tx $txh "waiting";
# upload another (third) scrt-rng and a second user
secretcli tx compute store user.wasm.gz --from a --gas 4000000 -y;
secretcli tx compute store user.wasm.gz --from b --gas 4000000 -y;
secretcli tx compute store user.wasm.gz --from c --gas 4000000 -y;
txh="$(tx_of secretcli tx compute store user.wasm.gz --from d --gas 4000000 -y)";
wait_for_tx $txh "waiting";

# secretcli query compute list-code

AA="$(secretcli keys show --address a)";  
BB="$(secretcli keys show --address b)";  
CC="$(secretcli keys show --address c)";  

# instantiate scrt-rng contracts
INIT='{"initseed": "initseed input String","prng_seed":"seed string here"}'; 
CODE_IDa=1; secretcli tx compute instantiate $CODE_IDa "$INIT" --from a --label "my ORACLE!" -y
CODE_IDb=2; secretcli tx compute instantiate $CODE_IDb "$INIT" --from b --label "my SECOND oracle!" -y
CODE_IDc=3; txh="$(tx_of secretcli tx compute instantiate $CODE_IDc "$INIT" --from c --label "my THIRD oracle!" -y)"
wait_for_compute_tx $txh "waiting";

CONTRACT="$(secretcli query compute list-contract-by-code $CODE_IDa | jq -er '.[].address')";
HASH="$(secretcli q compute contract-hash $CONTRACT | sed 's/^0x//')";
CONTRACT2="$(secretcli query compute list-contract-by-code $CODE_IDb | jq -er '.[].address')";
HASH2="$(secretcli q compute contract-hash $CONTRACT2 | sed 's/^0x//')";
CONTRACT3="$(secretcli query compute list-contract-by-code $CODE_IDc | jq -er '.[].address')";
HASH3="$(secretcli q compute contract-hash $CONTRACT3 | sed 's/^0x//')";

# secretcli query compute list-contract-by-code 1

# instantiate rn-user(s)
INIT='{"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}' 
CODE_IDa=4; secretcli tx compute instantiate $CODE_IDa "$INIT" --from a --label "rn USER!" -y
CODE_IDb=5; secretcli tx compute instantiate $CODE_IDb "$INIT" --from b --label "rn USER 2!" -y
CODE_IDc=6; secretcli tx compute instantiate $CODE_IDc "$INIT" --from c --label "rn USER 3!" -y
CODE_IDd=7; txh="$(tx_of secretcli tx compute instantiate $CODE_IDd "$INIT" --from d --label "rn USER 4!" -y)"
wait_for_compute_tx $txh "waiting";

USER="$(secretcli query compute list-contract-by-code $CODE_IDa | jq -er '.[].address')";
USER_H="$(secretcli q compute contract-hash $USER | sed 's/^0x//')";
USER2="$(secretcli query compute list-contract-by-code $CODE_IDb | jq -er '.[].address')";
USER2_H="$(secretcli q compute contract-hash $USER2 | sed 's/^0x//')";
USER3="$(secretcli query compute list-contract-by-code $CODE_IDc | jq -er '.[].address')";
USER3_H="$(secretcli q compute contract-hash $USER3 | sed 's/^0x//')";
USER4="$(secretcli query compute list-contract-by-code $CODE_IDd | jq -er '.[].address')";
USER4_H="$(secretcli q compute contract-hash $USER4 | sed 's/^0x//')";



# ########################################################################
# test functions
# ########################################################################

# ------------------------------------------------------------------------
# Option 0 functions
# ------------------------------------------------------------------------

function test_op0() {
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"request_rn":{"entropy":"foo bar"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    assert_eq "$(data_of secretcli q compute tx $txh | jq '.rn[]' | jq length)" 32
}

# ------------------------------------------------------------------------
# Option 1 functions
# ------------------------------------------------------------------------
function test_op1() {
    callbackmsg='message before RN'
    callbackbinary="$(base64 <<< $callbackmsg)" 
    # gas log for callback_rn called via cli

    txh0="$(tx_of secretcli tx compute execute $CONTRACT '{"callback_rn": {"entropy":"foo bar","cb_msg":"'"$callbackbinary"'", "callback_code_hash":"'"$HASH"'", "contract_addr":"'"$CONTRACT"'"}}' --gas 300000 --from a -y)";
    wait_for_compute_tx $txh0 "waiting for tx"
    log_gas $txh0 "callback_rn-through-cli"

    # User contract can callback_rn and receive cb_msg, and RN (seed) changes from the two consecutive callback_rn calls

    txh0="$(tx_of secretcli tx compute execute $USER '{"call_rn":{"entropy":"foo bar","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    txh1="$(tx_of secretcli tx compute execute $USER '{"call_rn":{"entropy":"foo bar","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
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
    # cb_msg0_msg="$1"
    # cb_msg0="$(base64 <<< $cb_msg0_msg)";
    # PURPOSE="$2"
    
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
    seed0="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq -r '.contract_config.seed')"
    
    txh5="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$CC"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh5 "waiting for tx"
    seed1="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq -r '.contract_config.seed')"
    
    echo "testing: create_rn and fulfill_rn"
    assert_ne "$(secretcli q compute tx $txh3 | jq '.output_log[]')" ""  #<---

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

    # User contract can create_rn and fulfill_rn. a: all fields with Some(), b: receiver_addr = None, c: purpose = None, d: max_blk_delay = None
    txh0a="$(tx_of secretcli tx compute execute $USER '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1,"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    txh0b="$(tx_of secretcli tx compute execute $USER2 '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER2_H"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1,"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    txh0c="$(tx_of secretcli tx compute execute $USER3 '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER3_H"'", "receiver_addr":"'"$USER3"'", "max_blk_delay":1,"rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from c --gas 300000 -y)"
    txh0d="$(tx_of secretcli tx compute execute $USER4 '{"trigger_create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER4_H"'", "receiver_addr":"'"$USER4"'", "purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from d --gas 300000 -y)"
    wait_for_compute_tx $txh0d "waiting"

    txh1a="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$USER"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    txh1b="$(tx_of secretcli tx compute execute $USER2 '{"trigger_fulfill_rn":{"creator_addr":"'"$USER2"'","receiver_code_hash":"'"$USER2_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    txh1c="$(tx_of secretcli tx compute execute $USER3 '{"trigger_fulfill_rn":{"creator_addr":"'"$USER3"'","receiver_code_hash":"'"$USER3_H"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from c --gas 300000 -y)"
    txh1d="$(tx_of secretcli tx compute execute $USER4 '{"trigger_fulfill_rn":{"creator_addr":"'"$USER4"'","receiver_code_hash":"'"$USER4_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from d --gas 300000 -y)"
    wait_for_compute_tx $txh1d "waiting"

    log_gas $txh0a "create_rn-via-rn_user"
    log_gas $txh1a "fulfill_rn-via-rn_user"

    echo "testing: contract create_rn" 
    for tx0 in $txh0a $txh0b $txh0c $txh0d; do
        assert_eq "$(secretcli q compute tx $tx0 | jq '.output_error[]')" ""  #<---
    done

    echo "testing: contract fulfill_rn: correct cb_msg: $cb_msg0_msg"
    for tx1 in $txh1a $txh1b $txh1c $txh1d; do
        assert_eq "$(secretcli q compute tx $tx1 | jq -r '.output_log[].attributes[] | select(.key=="cb_msg") | .value')" "$cb_msg0_msg" 
    done

    echo "testing: contract fulfill_rn: correct purpose: $PURPOSE"
    assert_eq "$(secretcli q compute tx $txh1a | jq -r '.output_log[].attributes[] | select(.key=="purpose") | .value')" "Some(\"$PURPOSE\")" 

    # testing: create RN and fulfill RN in same block -> error
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: create RN and fulfill RN in same block -> error"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[].msg')" "\"please wait for a short time between creating rn and transmitting rn"\"

    # max block delay. a: max_blk_delay=1 -> exceeded, b: max_blk_delay=None -> Ok
    txha="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    txhb="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER2_H"'", "receiver_addr":"'"$USER2"'", "purpose":"'"$PURPOSE"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txhb "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"request_rn": {"entropy":"foo bar"}}' --from a -y)"
    quiet_wait_for_compute_tx $txh "pausing..."
    txha="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    txhb="$(tx_of secretcli tx compute execute $USER2 '{"trigger_fulfill_rn":{"creator_addr":"'"$BB"'","receiver_code_hash":"'"$USER2_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txhb "waiting for tx"
    echo "testing: max block delay exceeded"
    assert_eq "$(secretcli q compute tx $txha | jq '.output_error[].msg')" '"delay between create_rn and transmit_rn exceeds max delay specified by user"'
    assert_eq "$(secretcli q compute tx $txhb | jq -r '.output_log[].attributes[] | select(.key=="cb_msg") | .value')" "$cb_msg0_msg" 

    # cannot fulfill_rn more than once
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from b --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx"
    echo "testing: cannot fulfill_rn more than once -- first attempt should succeed"
    assert_ne "$(secretcli q compute tx $txh | jq '.output_log[]')" "" #<---

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

# ------------------------------------------------------------------------
# Admin functions
# ------------------------------------------------------------------------

function test_admin_func() {
    # Save original config
    config0="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.')"

    # Admin can add new admin
    secretcli tx compute execute $CONTRACT '{"add_admin":{"add":"'"$BB"'"}}' --from a -y
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"add_admin":{"add":"'"$CC"'"}}' --from b -y)"
    wait_for_compute_tx $txh "waiting for tx";
    admin_count="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.admin' | jq length)"
    assert_eq $admin_count 3
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Admin can remove new admin c
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"remove_admin":{"remove":"'"$CC"'"}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    admin_count="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.admin' | jq length)"
    assert_eq $admin_count 2
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Creator or Admins cannot remove creator
    txha="$(tx_of secretcli tx compute execute $CONTRACT '{"remove_admin":{"remove":"'"$AA"'"}}' --from a -y)"
    txhb="$(tx_of secretcli tx compute execute $CONTRACT '{"remove_admin":{"remove":"'"$AA"'"}}' --from b -y)"
    wait_for_compute_tx $txhb "waiting for tx";
    admin_count="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.admin' | jq length)"
    assert_eq $admin_count 2
    assert_eq "$(secretcli q compute tx $txha | jq -r '.output_error[].msg')" "Cannot remove creator as admin" 
    assert_eq "$(secretcli q compute tx $txhb | jq -r '.output_error[].msg')" "Cannot remove creator as admin" 

    # New admin can change config (fwd entropy as test)
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_fwd":{"forw_entropy":true,"forw_entropy_to_hash":["'"$HASH2"'","'"$HASH3"'"],"forw_entropy_to_addr":["'"$CONTRACT2"'","'"$CONTRACT3"'"]}}' --from b -y)"
    wait_for_compute_tx $txh "waiting for tx";
    fwd_bool="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.forw_entropy')"
    assert_eq $fwd_bool "true"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Non-admin cannot add new admin
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"add_admin":{"add":"'"$DD"'"}}' --from c -y)"
    wait_for_compute_tx $txh "waiting for tx";
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error[].msg')" "This is an authenticated function" 

    # Non-admin cannot remove admin b
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"remove_admin":{"remove":"'"$BB"'"}}' --from c -y)"
    wait_for_compute_tx $txh "waiting for tx";
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error[].msg')" "This is an authenticated function" 

    # New admin can remove itself as admin
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"remove_admin":{"remove":"'"$BB"'"}}' --from b -y)"
    wait_for_compute_tx $txh "waiting for tx";
    admin_count="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.admin' | jq length)"
    assert_eq $admin_count 1
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Creator can change config: Change back settings to default
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_fwd":{"forw_entropy":false,"forw_entropy_to_hash":[],"forw_entropy_to_addr":[]}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    config1="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.')"
    echo "test_admin_func: config back to original"
    assert_eq "$config1" "$config0"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 
}

# ------------------------------------------------------------------------
# Forward entropy functions
# ------------------------------------------------------------------------

function test_fwd_entropy() {
    # Non-admin cannot access fwd entropy config function...
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_fwd":{"forw_entropy":true,"forw_entropy_to_hash":["'"$HASH2"'","'"$HASH3"'"],"forw_entropy_to_addr":["'"$CONTRACT2"'","'"$CONTRACT3"'"]}}' --from b -y)"
    wait_for_compute_tx $txh "waiting for tx";
    fwd_bool="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.forw_entropy')"
    assert_eq $fwd_bool "false"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error[].msg')" "This is an authenticated function" 

    # Admin can config forward entropy
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_fwd":{"forw_entropy":true,"forw_entropy_to_hash":["'"$HASH2"'","'"$HASH3"'"],"forw_entropy_to_addr":["'"$CONTRACT2"'","'"$CONTRACT3"'"]}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    fwd_bool="$(secretcli q compute query $CONTRACT '{"query_config": {}}' | jq '.contract_config.forw_entropy')"
    assert_eq $fwd_bool "true"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Forward entropy changes seed of Scrt-RNG 2, when: request_rn, callback_rn, create_rn, fulfill_rn
    seed0="$(secretcli q compute query $CONTRACT2 '{"query_config": {}}' | jq -r '.contract_config.seed')"
    seeda="$(secretcli q compute query $CONTRACT3 '{"query_config": {}}' | jq -r '.contract_config.seed')"

    txh0="$(tx_of secretcli tx compute execute $CONTRACT '{"request_rn":{"entropy":"foo bar"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh0 "waiting for tx"
    seed1="$(secretcli q compute query $CONTRACT2 '{"query_config": {}}' | jq -r '.contract_config.seed')"
    seedb="$(secretcli q compute query $CONTRACT3 '{"query_config": {}}' | jq -r '.contract_config.seed')"

    txh1="$(tx_of secretcli tx compute execute $USER '{"call_rn":{"entropy":"foo bar","cb_msg":"'"$callbackbinary"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh1 "waiting for tx";
    seed2="$(secretcli q compute query $CONTRACT2 '{"query_config": {}}' | jq -r '.contract_config.seed')"

    txh2="$(tx_of secretcli tx compute execute $CONTRACT '{"create_rn":{"entropy":"foo bar", "cb_msg":"'"$cb_msg0"'", "receiver_code_hash":"'"$USER_H"'", "receiver_addr":"'"$USER"'", "purpose":"'"$PURPOSE"'","max_blk_delay":1}}' --from a --gas 300000 -y)" 
    wait_for_compute_tx $txh2 "waiting for tx";
    seed3="$(secretcli q compute query $CONTRACT2 '{"query_config": {}}' | jq -r '.contract_config.seed')"

    txh3="$(tx_of secretcli tx compute execute $USER '{"trigger_fulfill_rn":{"creator_addr":"'"$AA"'","receiver_code_hash":"'"$USER_H"'","purpose":"'"$PURPOSE"'","rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from c --gas 300000 -y)"
    wait_for_compute_tx $txh3 "waiting for tx";
    seed4="$(secretcli q compute query $CONTRACT2 '{"query_config": {}}' | jq -r '.contract_config.seed')"

    echo "test_fwd_entropy: seed changed for every tx. $seed0 vs $seed1 vs $seed2 vs $seed3 vs $seed4"
    assert_ne $seed0 $seed1; assert_ne $seed1 $seed2; assert_ne $seed2 $seed3; assert_ne $seed3 $seed4
    assert_ne $seeda $seedb
    assert_ne $seed0 ""; assert_ne $seed1 ""; assert_ne $seed2 ""; assert_ne $seed3 ""; assert_ne $seed4 ""; assert_ne $seeda ""; assert_ne $seedb ""

    # log gas with fwd entropy (to two addrs)
    log_gas $txh0 "request_rn-with-fwd-entropy-to-two-contracts"
    log_gas $txh1 "callback_rn-via-rn_user-contract-with-fwd-entropy-to-two-contracts"
    log_gas $txh2 "create_rn-with-fwd-entropy-to-two-contracts"
    log_gas $txh3 "fulfill_rn-with-fwd-entropy-to-two-contracts"
}

# ------------------------------------------------------------------------
# Authenticated query checks
# ------------------------------------------------------------------------

function test_auth_queries() {
    # Non authenticated contract cannot generate VK
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_generate_vk":{"receiver_code_hash":"'"$USER_H"'", "rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: non authenticated contract cannot generate and receive viewing key"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error[].msg')" "This is an authenticated function" 

    # Non-admin cannot add auth contract
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_auth":{"add":"'"$USER"'"}}' --from b -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: Non-admin cannot add auth contract for vk"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error[].msg')" "This is an authenticated function" 

    # Admin can add auth contract
    txh="$(tx_of secretcli tx compute execute $CONTRACT '{"configure_auth":{"add":"'"$USER"'"}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: Admin can add auth contract for vk"
    assert_eq "$(secretcli q compute tx $txh | jq '.output_error[]')" "" 

    # Authenticated contract can generate VK
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_generate_vk":{"receiver_code_hash":"'"$USER_H"'", "rng_hash":"'"$HASH"'","rng_addr":"'"$CONTRACT"'"}}' --from a --gas 300000 -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: authenticated contract can generate and receive viewing key"
    vk1="$(secretcli q compute tx $txh | jq -r '.output_log[].attributes[] | select(.key=="added vk") | .value')"
    assert_eq ${vk1:0:8} "api_key_"

    # Authenticated contract can auth_query to get RN
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar"}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: authenticated contract can auth_query to get RN"
    assert_ne "$(secretcli q compute tx $txh | jq '.output_log[]')" "" #<--

    # Non authenticated contract cannot auth_query to get RN (wrong address or VK)
    txh="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar","optionalvk":"api_key_BobJLiwRSwnFgsI+6Mv2xUgTyNSF7Dob+DwUZDsaJkg="}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: Non authenticated contract cannot auth_query to get RN (wrong VK)"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "unauthorized"

    txh="$(tx_of secretcli tx compute execute $USER2 '{"trigger_query_rn":{"entropy":"foo bar","optionalvk":"'"$vk1"'"}}' --from a -y)"
    wait_for_compute_tx $txh "waiting for tx";
    echo "testing: Non authenticated contract cannot auth_query to get RN (wrong address)"
    assert_eq "$(secretcli q compute tx $txh | jq -r '.output_error | keys[]')" "unauthorized" 

    # Queries don't change RN
    txh0="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar"}}' --from a -y)"
    txh1="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar"}}' --from b -y)"
    wait_for_compute_tx $txh1 "waiting for tx";
    RN0="$(secretcli q compute tx $txh0 | jq -r '.output_log[].attributes[] | select(.key=="output")' | jq '.value')"
    RN1="$(secretcli q compute tx $txh1 | jq -r '.output_log[].attributes[] | select(.key=="output")' | jq '.value')"
    assert_eq "$RN0" "$RN1"

    # Contract-to-contract queries see mid-block states
    txh0="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar"}}' --from a -y)"
    txhmid="$(tx_of secretcli tx compute execute $CONTRACT '{"request_rn":{"entropy":"foo bar"}}' --from c --gas 300000 -y)"
    txh1="$(tx_of secretcli tx compute execute $USER '{"trigger_query_rn":{"entropy":"foo bar"}}' --from b -y)"
    wait_for_compute_tx $txh1 "waiting for tx";
    RN0="$(secretcli q compute tx $txh0 | jq -r '.output_log[].attributes[] | select(.key=="output")' | jq '.value')"
    RN1="$(secretcli q compute tx $txh1 | jq -r '.output_log[].attributes[] | select(.key=="output")' | jq '.value')"
    echo "Auth query tests: Contract-to-contract queries see mid-block states"
    assert_ne "$RN0" "$RN1"
    log_gas $txh0 "user-authenticated-query_rn"
}



# ########################################################################
# Execute tests
# ########################################################################

test_op0
test_op1
test_op2
test_admin_func
test_fwd_entropy
test_auth_queries

# Print gas usage
echo ""; echo "$gas_log"
echo ""; echo "ALL TESTS COMPLETED SUCCESSFULLY"
echo "warning: switch off ability to query seed, before launching on testnet or mainnet"
