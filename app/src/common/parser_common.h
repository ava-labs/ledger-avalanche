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
    parser_no_data,
    parser_display_idx_out_of_range,
    parser_display_page_out_of_range,
    parser_unexpected_error,
    parser_init_context_empty,
    parser_context_mismatch,
    parser_unexpected_type,
    parser_unexpected_field,
    parser_unexpected_buffer_end,
    parser_value_out_of_range,
    parser_invalid_address,
    parser_unexpected_number_items,
    parser_invalid_hash_mode,
    parser_invalid_signature,
    parser_invalid_pubkey_encoding,
    parser_invalid_address_version,
    parser_invalid_address_length,
    parser_invalid_type_id,
    parser_invalid_codec,
    parser_invalid_threshold,
    parser_invalid_network_id,
    parser_invalid_chain_id,
    parser_invalid_ascii_value,
    parser_invalid_timestamp,
    parser_invalid_staking_amount,
    parser_invalid_transaction_type,
    parser_operation_overflows,
    parser_unexpected_data,
    parser_invalid_path,
    parser_too_many_outputs,
    parser_invalid_avax_message,
    parser_invalid_eth_message,
    parser_invalid_eth_selector,
    parser_invalid_asset_call,
    parser_nft_info_not_provided,
    parser_invalid_contract_address,
    parser_context_unexpected_size,
} parser_error_t;
#include <stdint.h>

typedef enum {
    SignAvaxTx = 0x00, // Explicitly set to 0
    SignEthTx,         // Implicitly set to 1
    SignAvaxMsg,       // Implicitly set to 2
    SignEthMsg,        // Implicitly set to 3
    SignAvaxHash       // Implicitly set to 4
} instruction_t;


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
