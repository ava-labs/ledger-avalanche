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

zxerr_t addr_getNumItems(uint8_t *num_items) {
    if (num_items == NULL) {
        return zxerr_no_data;
    }
    // Display [public address | ivk | ovk | path]
    *num_items = 4;
    return zxerr_ok;
}

zxerr_t addr_getItem(int8_t displayIdx, char *outKey, uint16_t outKeyLen, char *outVal, uint16_t outValLen, uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(50, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Address");
            const char* address = (const char*)G_io_apdu_buffer;
            pageStringHex(outVal, outValLen, address, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 1:
            snprintf(outKey, outKeyLen, "IVK");
            const char* ivk = (const char*)G_io_apdu_buffer + KEY_LENGTH;
            pageStringHex(outVal, outValLen, ivk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 2:
            snprintf(outKey, outKeyLen, "OVK");
            const char* ovk = (const char*)G_io_apdu_buffer + 2 * KEY_LENGTH;
            pageStringHex(outVal, outValLen, ovk, KEY_LENGTH, pageIdx, pageCount);
            break;
        case 3: {
            snprintf(outKey, outKeyLen, "HD Path");
            char buffer[300];
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            break;
        }

        default:
            return zxerr_no_data;
    }

    return zxerr_ok;
}
