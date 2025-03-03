/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
#pragma once

#include <os_io_seproxyhal.h>
#include <stdint.h>
#include "cx.h"
#include "app_main.h"

#include "apdu_codes.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "zxerror.h"
#include "rslib.h"

extern uint16_t action_addrResponseLen;
extern uint16_t action_txResponseLen;

__Z_INLINE void clean_up_hash_globals() {
    _clean_up_hash(); 
}

__Z_INLINE void app_sign_hash(uint8_t curve_type) {
    zemu_log("app_sign_hash\n");

    uint32_t path[HDPATH_LEN_DEFAULT] = {0};
    uint8_t hash[CX_SHA256_SIZE] = {0};

    zxerr_t err = zxerr_ok;

    // get the hash, the path and pass it to our crypto signing function 
    // we should not use the global hdPath variable here as it is just the path prefix. 
    err = _get_hash(hash, CX_SHA256_SIZE);

    if (err != zxerr_ok) {
        zemu_log("Error getting hash\n");
        set_code(G_io_apdu_buffer, 0, APDU_CODE_EXECUTION_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    // Do a partial parsing of the received path suffix
    uint8_t path_len = G_io_apdu_buffer[OFFSET_DATA];
    uint8_t len_bytes = path_len * sizeof(uint32_t) + 1;

    { 
        char data[100];
        snprintf(data, sizeof(data), "Path len: %d\n", path_len);
        zemu_log(data);
    }

    // include 1-bytes for len
    err = _get_signing_info(path, HDPATH_LEN_DEFAULT, &G_io_apdu_buffer[OFFSET_DATA], len_bytes);

    if (err != zxerr_ok) {
        zemu_log("Error getting signing info\n");
        set_code(G_io_apdu_buffer, 0, APDU_CODE_EXECUTION_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    err = crypto_sign_avax(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, hash, CX_SHA256_SIZE, path, HDPATH_LEN_DEFAULT, curve_type);

    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_EXECUTION_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        // ensure we clean paths and hashes
        if (G_io_apdu_buffer[OFFSET_P1] == LAST_MESSAGE)
            clean_up_hash_globals();

        if (curve_type == CURVE_ED25519) {
            set_code(G_io_apdu_buffer, ED25519_SIGNATURE_SIZE, APDU_CODE_OK);
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, ED25519_SIGNATURE_SIZE + 2);
        } else {
            set_code(G_io_apdu_buffer, SECP256K1_PK_LEN, APDU_CODE_OK);
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, SECP256K1_PK_LEN + 2);
        }
    }

}

__Z_INLINE void app_sign(uint16_t offset) {
    zemu_log_stack("app_sign");

    // needs to remove the change_path list
    const uint8_t *data = tx_get_buffer();
    const uint16_t data_len = tx_get_buffer_length();

    uint8_t message[CX_SHA256_SIZE];

    cx_hash_sha256(data + offset, data_len - offset, message, CX_SHA256_SIZE);

    // Set hash in Rust side for the next stage:
    zxerr_t err = _set_tx_hash(message, CX_SHA256_SIZE);

    if (err != zxerr_ok) {
        set_code(G_io_apdu_buffer, 0, APDU_CODE_EXECUTION_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    } else {
        // we are just returning the CODE_OK
        // the signature would be returned in the next stage.
        set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    }
}

__Z_INLINE void app_sign_tx() {
    zemu_log_stack("app_sign_tx");

    // needs to remove the change_path list
    const uint8_t *data = tx_get_buffer();
    const uint16_t data_len = tx_get_buffer_length();

    uint16_t offset = 0;

    // This is necessary so we skip the change_path list
    if (_tx_data_offset(data, data_len, &offset) != zxerr_ok) {
        zemu_log_stack("TX_DATA_OFFSET error\n");
        set_code(G_io_apdu_buffer, 0, APDU_CODE_EXECUTION_ERROR);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    app_sign(offset);
}

__Z_INLINE void app_sign_msg() {
    zemu_log_stack("app_sign");

    // no change paths list at the begining
    app_sign(0);
}

// no change paths list at the begining
__Z_INLINE void app_sign_hash_review() {
    zemu_log_stack("app_sign_hash_review");

    // we are just returning the CODE_OK
    // the hash signature would be returned in the next stage.
    set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reject() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}

__Z_INLINE void wallet_reply() {
    set_code(G_io_apdu_buffer, action_addrResponseLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponseLen + 2);
}


__Z_INLINE void app_reply_error() {
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_sign_eth() {
    zemu_log_stack("app_sign_hash_review");

    uint16_t ret = _accept_eth_tx(&action_txResponseLen, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    // We expect a signature
    if (action_txResponseLen != SECP256K1_PK_LEN) {
        zemu_log("Invalid response length\n");
        set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    if (ret != APDU_CODE_OK) {
        set_code(G_io_apdu_buffer, 0, ret);
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
        return;
    }

    set_code(G_io_apdu_buffer, SECP256K1_PK_LEN, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, SECP256K1_PK_LEN + 2);
}

__Z_INLINE void app_eth_configuration() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    uint16_t replyLen = 4;

    G_io_apdu_buffer[0] = 0x02; //needs external data for ERC20 tokens
    G_io_apdu_buffer[1] = APPVERSION_M;
    G_io_apdu_buffer[2] = APPVERSION_N;
    G_io_apdu_buffer[3] = APPVERSION_P;


    set_code(G_io_apdu_buffer, replyLen, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, replyLen + 2);
}

