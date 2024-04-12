#pragma once

#include <stdint.h>
#include "parser_common.h"
// #include "keys_def.h"
#include "parser_txdef.h"

/* Interface functions with jubjub crate */
// parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
// parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);

/****************************** others ***********************************************************/

parser_error_t _init_avax_tx(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize, uint16_t *alloc_size);

parser_error_t _read_avax_tx(const parser_context_t *c, parser_tx_t *v);

parser_error_t _validate(const parser_context_t *ctx, const parser_tx_t *v);

parser_error_t _getNumItems(const parser_context_t *ctx, const parser_tx_t *v, uint8_t *num_items);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount,
                              const parser_tx_t *v);




