#pragma once

#include <stdint.h>
#include "parser_common.h"
// #include "keys_def.h"
#include "parser_txdef.h"

/* Interface functions with jubjub crate */
// parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
// parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);

/****************************** others ***********************************************************/

parser_error_t _parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize, uint16_t *alloc_size);

parser_error_t _parser_read(const parser_context_t *c, parser_tx_t *v);

parser_error_t _validate(const parser_context_t *ctx, const parser_tx_t *v);

parser_error_t _getNumItems(const parser_context_t *ctx, const parser_tx_t *v, uint8_t *num_items);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount,
                              const parser_tx_t *v);

// To handle an public key and address requests, without 
// confirmation(UI)
uint16_t _app_fill_address(
    uint32_t *tx,
    uint32_t rx,
    uint8_t *buffer,
    uint16_t buffer_len,
    uint8_t *addr_obj,
    uint16_t addr_obj_len
);

uint16_t _address_ui_size();

zxerr_t _addr_num_items(uint8_t *addr_obj, uint16_t *num_items);
zxerr_t _addr_get_item(
    uint8_t *addr_obj,
    uint8_t display_idx,
    uint8_t *out_key,
    uint16_t key_len,
    uint8_t *out_value,
    uint16_t out_len,
    uint8_t page_idx,
    uint8_t *page_count);
