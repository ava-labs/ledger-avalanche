/*******************************************************************************
 *   (c) 2018 - 2023 Zondax AG
 *   (c) 2016 Ledger
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"
#include "parser_common.h"
#include "rslib.h"

static bool tx_initialized = false;

void extractHDPath(uint32_t rx, uint32_t offset) {
    tx_initialized = false;

    if (rx < offset + 1) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint8_t path_len = G_io_apdu_buffer[offset];
    uint8_t len_bytes = path_len * sizeof(uint32_t);

    if (path_len > HDPATH_LEN_DEFAULT || (rx - (offset + 1)) < len_bytes) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    memcpy(hdPath, G_io_apdu_buffer + offset + 1, len_bytes);
    // we need to pass this root path to rust,
    // later we can make rust ask for it but it would change other logic 
    // in the crypto module.
    // len_bytes + 1 to include the first byte that tells the number  
    // of elements in the path list
    _set_root_path(&G_io_apdu_buffer[offset], len_bytes + 1);
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE]) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            // we are appending the change_path list which 
            // needs to be removed before signing
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
    }

    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetAddr\n");

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    zxerr_t zxerr = fill_address(flags, tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignAvaxTx(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignAvaxTx\n");
    // This is the first transaction signing stage, where we receive the root path 
    // to be used for change_outputs and signers. so we need to tell process_chunk 
    // to parse it.
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    const char *error_msg = tx_avax_parse();

    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        zemu_log(error_msg);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignAvaxHash(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignAvaxHash\n");

    // we do not need to process_chunk 
    // all data was send in one go
    // and for now we are not ussing transaction buffer for this
    // if (!process_chunk(tx, rx, is_first_message)) {
    //     THROW(APDU_CODE_OK);
    // }

    // in this case we just received a path suffix 
    // we are supposed to use the previously stored 
    // root_path and hash
    if (G_io_apdu_buffer[OFFSET_P1] != FIRST_MESSAGE) {
        app_sign_hash();
    } else {
        // this is the sign_hash transaction 
        // we received in one go the root path 
        // and 32-bytes hash
        // so append it to our internal buffer and parse it
        tx_initialize();
        tx_reset();
        // this step is not really necessary
        extractHDPath(rx, OFFSET_DATA);

        uint16_t added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);

        if (added != rx - OFFSET_DATA) {
            THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
        }

        const char *error_msg = tx_avax_parse_hash();
        CHECK_APP_CANARY()

        if (error_msg != NULL) {

            const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
            memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
            *tx += (error_msg_length);
            THROW(APDU_CODE_DATA_INVALID);
        }

        view_review_init(tx_getItem, tx_getNumItems, app_sign_hash);
        view_review_show(REVIEW_TXN);
    }

    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignAvaxMsg(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignAvaxMsg\n");

    // This is a message that comes with a root path and raw bytes to be signed
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    const char *error_msg = tx_avax_parse_msg();

    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        zemu_log(error_msg);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}


__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (LEDGER_MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (LEDGER_MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (LEDGER_MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (LEDGER_MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (LEDGER_PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (LEDGER_PATCH_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[7] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

#if defined(APP_TESTING)
void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) { THROW(APDU_CODE_OK); }
#endif

__Z_INLINE void avax_dispatch(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("AVAX Dispatch\n");
    switch (G_io_apdu_buffer[OFFSET_INS]) {
        case INS_GET_VERSION: {
            handle_getversion(flags, tx);
            break;
        }
        case AVX_GET_PUBLIC_KEY: {
            CHECK_PIN_VALIDATED()
            handleGetAddr(flags, tx, rx);
            break;
        }
        case AVX_SIGN: {
            CHECK_PIN_VALIDATED()
            handleSignAvaxTx(flags, tx, rx);
            break;
        }

        case AVX_SIGN_HASH: {
            CHECK_PIN_VALIDATED()
            handleSignAvaxHash(flags, tx, rx);

            break; 
        }

        case AVX_SIGN_MSG: {
            CHECK_PIN_VALIDATED()
            handleSignAvaxMsg(flags, tx, rx);

            break; 
        }
        default: {
            zemu_log("unknown_instruction***\n");
            THROW(APDU_CODE_INS_NOT_SUPPORTED);
        }
    }
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != AVX_CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            if (G_io_apdu_buffer[OFFSET_CLA] == AVX_CLA) {
                avax_dispatch(flags, tx, rx);
            }

            // Process non-avax instruction
            switch (G_io_apdu_buffer[OFFSET_INS]) {

#if defined(APP_TESTING)
                case INS_TEST: {
                    handleTest(flags, tx, rx);
                    THROW(APDU_CODE_OK);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY {}
    }
    END_TRY;
}
