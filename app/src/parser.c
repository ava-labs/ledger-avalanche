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

#include "common/parser.h"

#include <stdio.h>
#include <zxformat.h>
#include <zxmacros.h>
#include <zxtypes.h>

#include "coin.h"
#include "crypto.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "rslib.h"

static zxerr_t parser_allocate();

// This buffer will store parser_state.
// Its size corresponds to ParsedObj (Rust struct)
// Maximum required size: 256 bytes
#define PARSER_BUFFER_SIZE 256
static uint8_t parser_buffer[PARSER_BUFFER_SIZE];

// This function is used to allocate memory for the parser state
zxerr_t parser_allocate(parser_tx_t *parser_state) {
    if (parser_state->len % 4 != 0) {
        parser_state->len += parser_state->len % 4;
    }
    if(parser_state->len > PARSER_BUFFER_SIZE) {
        return zxerr_buffer_too_small;
    }
    if(parser_state->state != NULL) {
        return zxerr_unknown;
    }

    MEMZERO(parser_buffer, PARSER_BUFFER_SIZE);
    parser_state->state = (uint8_t *)&parser_buffer;
    return zxerr_ok;
}

// Initialized parser context and state
parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    if (bufferSize == 0 || buffer == NULL || ctx == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;
    return parser_ok;
}

// This function is used for parsing input data.
// internally it takes care of initializing parser state and context.
// some calls to rust are required, specially to get the parsed objecd size.
parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    ctx->tx_obj.state = NULL;
    ctx->tx_obj.len = 0;
    uint32_t size = 0;

    // initialized data on rust side, this include to get 
    // the size of the object to be parsed according to the 
    // tx type.
    CHECK_ERROR(_parser_init(ctx, data, dataLen, &size));

    if (size == 0) {
        return parser_context_unexpected_size;
    }
    ctx->tx_obj.len = size;

    if(parser_allocate(&ctx->tx_obj) != zxerr_ok) {
        return parser_init_context_empty ;
    }

    // Populate/Initialized parsed object 
    // by parsing the input data.
    parser_error_t err = _parser_read(ctx);

    return err; 
}

// Similates UI flow, this reduces the risk of stack overflow, 
// bad pointer aritmetic and other issues during UI.
parser_error_t parser_validate(const parser_context_t *ctx) {
    zemu_log("parser_validate\n");
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40] = {0};
    char tmpVal[40] = {0};

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    if (_getNumItems(ctx, num_items) != parser_ok) {
        return parser_unexpected_number_items;
    }
    if (*num_items == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
}

static void cleanOutput(char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx) {
    if (displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx, uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    // Calls rust getter
    return _getItem(ctx, displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_getNumItemsBlindSign(uint8_t *num_items) {
    if (_getNumItemsBlindSign(num_items) != parser_ok) {
        return parser_unexpected_number_items;
    }
    if (*num_items == 0) {
        return parser_unexpected_number_items;
    }
    return parser_ok;
}

parser_error_t parser_getItemBlindSign(uint8_t displayIdx, char *outKey, uint16_t outKeyLen,
                                       char *outVal, uint16_t outValLen, uint8_t pageIdx, uint8_t *pageCount) {
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItemsBlindSign(&numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    // Calls rust getter
    return _getItemBlindSign(displayIdx, outKey, outKeyLen, outVal, outValLen, pageIdx, pageCount);
}
