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

#include "parser_impl.h"

 const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_display_idx_out_of_range:
            return "Display index out of range";
        case parser_display_page_out_of_range:
            return "Display page out of range";
        case parser_unexpected_error:
            return "Unexpected error occurred";
        case parser_init_context_empty:
            return "Context is empty";
        case parser_context_mismatch:
            return "Context mismatch";
        case parser_unexpected_type:
            return "Unexpected type encountered";
        case parser_unexpected_field:
            return "Unexpected field encountered";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_invalid_hash_mode:
            return "Invalid hash mode specified";
        case parser_invalid_signature:
            return "Invalid signature format";
        case parser_invalid_pubkey_encoding:
            return "Invalid public key encoding";
        case parser_invalid_address_version:
            return "Invalid address version";
        case parser_invalid_address_length:
            return "Invalid address length";
        case parser_invalid_type_id:
            return "Invalid type ID specified";
        case parser_invalid_codec:
            return "Invalid codec used";
        case parser_invalid_threshold:
            return "Invalid threshold value";
        case parser_invalid_network_id:
            return "Invalid network ID specified";
        case parser_invalid_chain_id:
            return "Invalid chain ID specified";
        case parser_invalid_ascii_value:
            return "Invalid ASCII value found";
        case parser_invalid_timestamp:
            return "Invalid timestamp specified";
        case parser_invalid_staking_amount:
            return "Invalid staking amount";
        case parser_invalid_transaction_type:
            return "Invalid transaction type";
        case parser_operation_overflows:
            return "Operation causes overflow";
        case parser_unexpected_data:
            return "Unexpected data found";
        case parser_invalid_path:
            return "Invalid path specified";
        case parser_too_many_outputs:
            return "Too many outputs specified";
        case parser_invalid_avax_message:
            return "Invalid AVAX message format";
        case parser_invalid_eth_message:
            return "Invalid Ethereum message format";
        case parser_invalid_eth_selector:
            return "Invalid Ethereum selector used";
        case parser_invalid_asset_call:
            return "Invalid asset call";
        case parser_nft_info_not_provided:
            return "NFT information not provided";
        case parser_invalid_contract_address:
            return "Invalid contract address specified";
        case parser_context_unexpected_size:
            return "Unexpected context size";
        default:
            return "Unrecognized error code\n";
    }
}
