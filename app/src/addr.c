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

#include <stdio.h>

#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"
#include "keys_def.h"
#include "os.h"
#include "rslib.h"
#include "actions.h"

#define ASCII_HRP_MAX_SIZE 24
#define MAX_CHAIN_CB58_LEN 50
#define CHAIN_ID_CHECKSUM_SIZE 4
#define CHAIN_CODE_LEN 32
#define ADDR_UI_MAX_SIZE 62

// Use to hold the addr_ui object, used by rust to display the address
uint8_t addr_ui_obj[ADDR_UI_MAX_SIZE] = {0};



zxerr_t fill_address(
    uint32_t *flags,
    uint32_t *tx,
    uint32_t rx,
    uint8_t *buffer,
    uint16_t buffer_len
) {

    zemu_log("fill_address\n");

    zxerr_t err = _app_fill_address(tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE, addr_ui_obj, ADDR_UI_MAX_SIZE);

    if (err != zxerr_ok)
        action_addrResponseLen = 0;

    action_addrResponseLen = *tx;
    return err;
}

zxerr_t addr_getNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    return _addr_num_items(addr_ui_obj, num_items);
}

zxerr_t addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    return _addr_get_item(addr_ui_obj, displayIdx, (uint8_t*)outKey, outKeyLen, (uint8_t*)outVal, outValLen, pageIdx, pageCount);
}
