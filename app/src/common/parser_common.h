/*******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "parser_txdef.h"

#define CHECK_ERROR(__CALL)                   \
    {                                         \
        parser_error_t __err = __CALL;        \
        CHECK_APP_CANARY()                    \
        if (__err != parser_ok) return __err; \
    }

typedef enum {
    parser_ok = 0,
    parser_no_data = 1,
    parser_display_idx_out_of_range = 2,
    parser_display_page_out_of_range = 3,
    parser_unexpected_error = 4,
    parser_init_context_empty = 5,
    parser_context_mismatch = 6,
    parser_unexpected_type = 7,
    parser_unexpected_field = 8,
    parser_unexpected_buffer_end = 9,
    parser_value_out_of_range = 10,
    parser_invalid_address = 11,
    parser_unexpected_number_items = 12,
    parser_invalid_hash_mode = 13,
    parser_invalid_signature = 14,
    parser_invalid_pubkey_encoding = 15,
    parser_invalid_address_version = 16,
    parser_invalid_address_length = 17,
    parser_invalid_type_id = 18,
    parser_invalid_codec = 19,
    parser_invalid_threshold = 20,
    parser_invalid_network_id = 21,
    parser_invalid_chain_id = 22,
    parser_invalid_ascii_value = 23,
    parser_invalid_timestamp = 24,
    parser_invalid_staking_amount = 25,
    parser_invalid_transaction_type = 26,
    parser_operation_overflows = 27,
    parser_unexpected_data = 28,
    parser_invalid_path = 29,
    parser_too_many_outputs = 30,
    parser_invalid_avax_message = 31,
    parser_invalid_eth_message = 32,
    parser_invalid_eth_selector = 33,
    parser_invalid_asset_call = 34,
    parser_nft_info_not_provided = 35,
    parser_invalid_contract_address = 36,
    parser_context_unexpected_size = 37,
    parser_blind_sign_not_enabled = 42,
} parser_error_t;
#include <stdint.h>

typedef enum { SignAvaxTx = 0x00, SignEthTx, SignAvaxMsg, SignEthMsg, SignAvaxHash, EthAddr } instruction_t;

typedef struct {
    const uint8_t *buffer;
    uint16_t bufferLen;
    uint16_t offset;
    instruction_t ins;
    parser_tx_t tx_obj;
} parser_context_t;

#ifdef __cplusplus
}
#endif
