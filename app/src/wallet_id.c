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

#define WALLET_UI_MAX_SIZE 6

// Use to hold the addr_ui object, used by rust to display the address
uint8_t addr_ui_obj[WALLET_UI_MAX_SIZE] = {0};

zxerr_t fill_wallet_id(
    uint32_t *tx,
    uint32_t rx,
    uint8_t *buffer,
    uint16_t buffer_len
) {

    uint16_t ui = _wallet_ui_size();

    { 
        char data[100];
        snprintf(data, sizeof(data), "ui_len: %d\n", ui);
        zemu_log(data);
    }

    zxerr_t err = _app_fill_wallet(tx, rx, buffer, buffer_len, addr_ui_obj, WALLET_UI_MAX_SIZE);

    if (err != zxerr_ok)
        action_addrResponseLen = 0;

    action_addrResponseLen = *tx;
    return err;
}

zxerr_t wallet_getNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    return _wallet_num_items(addr_ui_obj, num_items);
}

zxerr_t wallet_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    return _wallet_get_item(addr_ui_obj, displayIdx, (unsigned char*)outKey, outKeyLen, (unsigned char*)outVal, outValLen, pageIdx, pageCount);
}
