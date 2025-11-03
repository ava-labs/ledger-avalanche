/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

#include "tx.h"

#include <string.h>

#include "apdu_codes.h"
#include "buffering.h"
#include "common/parser.h"
#include "parser_common.h"
#include "zxmacros.h"

#if defined(LEDGER_SPECIFIC)
#define RAM_BUFFER_SIZE 7168
#define FLASH_BUFFER_SIZE 16384
#endif

// Ram
uint8_t ram_buffer[RAM_BUFFER_SIZE];

// Flash
typedef struct {
    uint8_t buffer[FLASH_BUFFER_SIZE];
} storage_t;

#if defined(LEDGER_SPECIFIC)
storage_t NV_CONST N_appdata_impl __attribute__((aligned(64)));
#define N_appdata (*(NV_VOLATILE storage_t *)PIC(&N_appdata_impl))
#endif

// Use the parser_tx_t object from the parser_context_t type
static parser_context_t ctx_parsed_tx;

const char *tx_parse();

void tx_initialize() {
    buffering_init(ram_buffer, sizeof(ram_buffer), (uint8_t *)N_appdata.buffer, sizeof(N_appdata.buffer));
}

void tx_reset() { buffering_reset(); }

uint32_t tx_append(unsigned char *buffer, uint32_t length) { return buffering_append(buffer, length); }

uint32_t tx_get_buffer_length() { return buffering_get_buffer()->pos; }

uint8_t *tx_get_buffer() { return buffering_get_buffer()->data; }

const char *tx_parse() {
    parser_error_t err = parser_parse(&ctx_parsed_tx, tx_get_buffer(), tx_get_buffer_length());

    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    err = parser_validate(&ctx_parsed_tx);
    CHECK_APP_CANARY()

    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }

    return NULL;
}

const char *tx_avax_parse() {
    MEMZERO(&ctx_parsed_tx.tx_obj, sizeof(parser_tx_t));
    // This is an avax transaction either P, X or C chain
    ctx_parsed_tx.ins = SignAvaxTx;

    return tx_parse();
}

const char *tx_avax_parse_hash() {
    MEMZERO(&ctx_parsed_tx.tx_obj, sizeof(parser_tx_t));
    // This is an avax transaction either P, X or C chain
    ctx_parsed_tx.ins = SignAvaxHash;

    return tx_parse();
}

const char *tx_avax_parse_msg() {
    MEMZERO(&ctx_parsed_tx.tx_obj, sizeof(parser_tx_t));
    ctx_parsed_tx.ins = SignAvaxMsg;

    return tx_parse();
}
void tx_eth_tx() { ctx_parsed_tx.ins = SignEthTx; }

void tx_eth_msg() { ctx_parsed_tx.ins = SignEthMsg; }

void tx_eth_addr() { ctx_parsed_tx.ins = EthAddr; }

void tx_parse_reset() { MEMZERO(&ctx_parsed_tx.tx_obj, sizeof(parser_tx_t)); }

zxerr_t tx_getNumItems(uint8_t *num_items) {
    parser_error_t err = parser_getNumItems(&ctx_parsed_tx, num_items);

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

zxerr_t tx_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                   uint8_t *pageCount) {
    uint8_t numItems = 0;

    CHECK_ZXERR(tx_getNumItems(&numItems))

    if (displayIdx > numItems) {
        return zxerr_no_data;
    }

    parser_error_t err =
        parser_getItem(&ctx_parsed_tx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);

    // Convert error codes
    if (err == parser_no_data || err == parser_display_idx_out_of_range || err == parser_display_page_out_of_range) {
        return zxerr_no_data;
    }

    if (err != parser_ok) {
        return zxerr_unknown;
    }

    return zxerr_ok;
}

const char *tx_err_msg_from_code(parser_error_t err) {
    if (err != parser_ok) {
        return parser_getErrorDescription(err);
    }
    return NULL;
}
