#pragma once

#include <stdint.h>
#include "parser_common.h"
// #include "keys_def.h"
#include "parser_txdef.h"

/* Interface functions with jubjub crate */
// parser_error_t from_bytes_wide(const uint8_t input[64], uint8_t output[32]);
// parser_error_t scalar_multiplication(const uint8_t input[32], constant_key_t key, uint8_t output[32]);

/****************************** others ***********************************************************/

parser_error_t _parser_init(parser_context_t *ctx, const uint8_t *buffer, size_t bufferSize, uint32_t *alloc_size);

parser_error_t _parser_read(const parser_context_t *c);

parser_error_t _validate(const parser_context_t *ctx);

parser_error_t _getNumItems(const parser_context_t *ctx, uint8_t *num_items);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount);

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

// To handle an public key and address requests, without 
// confirmation(UI)
uint16_t _fill_eth_address(
    uint32_t *tx,
    uint32_t rx,
    uint8_t *buffer,
    uint16_t buffer_len,
    uint8_t *addr_obj,
    uint16_t addr_obj_len
);

uint16_t _address_ui_size();
uint16_t _eth_address_ui_size();

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

zxerr_t _eth_addr_num_items(uint8_t *addr_obj, uint16_t *num_items);

zxerr_t _eth_addr_get_item(
    uint8_t *addr_obj,
    uint8_t display_idx,
    uint8_t *out_key,
    uint16_t key_len,
    uint8_t *out_value,
    uint16_t out_len,
    uint8_t page_idx,
    uint8_t *page_count);

// Set on the rust side the root path. 
// path_len is in bytes
void _set_root_path(const uint8_t *path, uint16_t path_len);

// Set the AVAX transaction hash, for the next step where we sign that hash with a list 
// of signers.
zxerr_t _set_tx_hash(uint8_t *hash, uint16_t hash_len_bytes);

// returns and offset from which the actual transaction data starts
// in case of error, this functions returns -1
zxerr_t _tx_data_offset(uint8_t *buffer, uint16_t buffer_len, uint16_t *offset);

zxerr_t _get_hash(uint8_t *hash, uint16_t hash_len);
// gets the path(root_path + suffix_path?) to sign a hash
zxerr_t _get_signing_info(uint32_t *path, uint16_t path_len, uint8_t *input, uint16_t input_len);

parser_error_t _parse_sign_hash_tx(uint8_t *input,  uint16_t len);

void _clean_up_hash();

uint8_t _computeV(parser_context_t *ctx, uint8_t parity);

zxerr_t _process_nft_info(uint8_t *buffer, uint16_t buffer_len);

uint64_t _eth_chain_id(parser_context_t *ctx);
