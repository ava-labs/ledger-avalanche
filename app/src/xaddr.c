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

#include "actions.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "keys_def.h"
#include "os.h"
#include "rslib.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

#define ADDR_UI_MAX_SIZE 62

// Use to hold the addr_ui object, used by rust to display the address
uint8_t xaddr_ui_obj[ADDR_UI_MAX_SIZE] = {0};

zxerr_t fill_ext_address(__Z_UNUSED uint32_t *flags, uint32_t *tx, uint32_t rx, uint8_t *buffer, uint16_t buffer_len) {
    zemu_log("fill_ext_address\n");

    zxerr_t err = _app_fill_ext_address(tx, rx, buffer, buffer_len, xaddr_ui_obj, ADDR_UI_MAX_SIZE);

    if (err != zxerr_ok) action_addrResponseLen = 0;

    action_addrResponseLen = *tx;
    return err;
}

zxerr_t xaddr_getNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    return _xaddr_num_items(xaddr_ui_obj, num_items);
}

zxerr_t xaddr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                      uint8_t *pageCount) {
    return _xaddr_get_item(xaddr_ui_obj, displayIdx, (unsigned char *)outKey, outKeyLen, (unsigned char *)outVal, outValLen,
                           pageIdx, pageCount);
}
