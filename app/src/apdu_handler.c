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
#include <app_mode.h>

#include "actions.h"
#include "addr.h"
#include "xaddr.h"
#include "wallet_id.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"
#include "parser_common.h"
#include "rslib.h"
#include "commands.h"
#if defined(FEATURE_ETH)
#include "handler.h"
#endif

static bool tx_initialized = false;

bool
is_eth_path(uint32_t rx, uint32_t offset)
{
    uint32_t path_len = *(G_io_apdu_buffer + offset);

    if (path_len > MAX_BIP32_PATH || path_len < 1)
        THROW(APDU_CODE_WRONG_LENGTH);

    if ((rx - offset - 1) < sizeof(uint32_t) * path_len) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    // first byte at OFFSET_DATA is the path len, so we skip this
    uint8_t *path_data = G_io_apdu_buffer + offset + 1;
    uint32_t ethPath[HDPATH_LEN_DEFAULT] = {0};

    // hw-app-eth serializes path as BE numbers
    for (uint8_t i = 0; i < path_len; i++) {
        ethPath[i] = U4BE(path_data, 0);
        path_data += sizeof(uint32_t);
    }

    const bool mainnet =
      ethPath[0] == HDPATH_ETH_0_DEFAULT && ethPath[1] == HDPATH_ETH_1_DEFAULT;

    return mainnet;
}

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
    zxerr_t zxerr = fill_address((uint32_t *)flags, (uint32_t*)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
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

__Z_INLINE void handleGetXAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetXAddr\n");

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    zxerr_t zxerr = fill_ext_address((uint32_t*)flags, (uint32_t*)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(xaddr_getItem, xaddr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetWalletId(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetWalletId\n");

    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = fill_wallet_id((uint32_t*)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    if (zxerr != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(wallet_getItem, wallet_getNumItems, wallet_reply);
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

    view_review_init(tx_getItem, tx_getNumItems, app_sign_tx);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignAvaxHash(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignAvaxHash\n");

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

        uint16_t added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);

        if (added != rx - OFFSET_DATA) {
            THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
        }

        const char *error_msg = tx_avax_parse_hash();
        CHECK_APP_CANARY()

        if (error_msg != NULL) {
            zemu_log(error_msg);
            const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
            memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
            *tx += (error_msg_length);
            THROW(APDU_CODE_DATA_INVALID);
        }

        view_review_init(tx_getItem, tx_getNumItems, app_sign_hash_review);
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

    view_review_init(tx_getItem, tx_getNumItems, app_sign_msg);
    view_review_show(REVIEW_MSG);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx) {
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (PATCH_VERSION >> 0) & 0xFF;

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

// Handles APDU command related to avalanche transactions, message, addresses and keys.
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

        case AVX_INS_GET_EXTENDED_PUBLIC_KEY: {
            CHECK_PIN_VALIDATED()
            handleGetXAddr(flags, tx, rx);
            break;
        }
        case AVX_INS_GET_WALLET_ID: {
            CHECK_PIN_VALIDATED()
            handleGetWalletId(flags, tx, rx);
            break;
        }

        default: {
            zemu_log("unknown_instruction***\n");
            THROW(APDU_CODE_INS_NOT_SUPPORTED);
        }
    }
}

__Z_INLINE void handleEthConfig(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleEthConfig\n");
    *tx = 0;
    app_eth_configuration();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleNftInfo(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleNftInfo\n");

    // the hw-app-eth sends all the data that is required for this.
    // it is arount 90 bytes length so It should error in case It received
    // less than that
    zxerr_t err = _process_nft_info(&G_io_apdu_buffer[OFFSET_DATA], rx - OFFSET_DATA);
    zemu_log("processed_nft_info\n");

    CHECK_APP_CANARY()

    if (err != zxerr_ok) {
        const char *error_msg = "Error processing NFT info";
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    *flags |= IO_ASYNCH_REPLY;
}


__Z_INLINE void handleProvideErc20(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleProvideErc20\n");

    // Nothing to do as we do not handle this information,
    // but need to return ok to ethereumjs-wallet in order to
    // ontinue with signing contract calls
    *tx = 0;

    set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSetPlugin(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSetPlugin\n");

    // This instruction is sent in the process of providing
    // more information regarding contract calls like erc721
    // nft token information, we need to return ok for this
    // in order the hw-app-eth package to continue with the
    // provide_token_info/provide_erc20_info instructions
    *tx = 0;

    zemu_log("processing_set_plugin\n");
    set_code(G_io_apdu_buffer, 0, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleSignEthMsg(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignEthMsg\n");

    tx_eth_msg();

    bool done = false;
    // cast to integer pointer, because app-ethereum expects them as plain pointers
    const char *error_msg = tx_err_msg_from_code(rs_eth_handle((uint32_t *)flags, (uint32_t *)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE, &done));

    // Wait for all transaction data to be processed
    if (!done) {
        THROW(APDU_CODE_OK);
    }

    if (error_msg != NULL) {
        zemu_log(error_msg);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init_progressive(tx_getItem, tx_getNumItems, app_sign_eth);
    view_review_show(REVIEW_MSG);

    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void
handleGetAddrEth(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx)
{

    tx_eth_addr();

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    // not needed as address data is not that large
    bool done = false;
    // cast to integer pointer, because app-ethereum expects them as plain pointers
    const char *error_msg = tx_err_msg_from_code(rs_eth_handle((uint32_t *)flags, (uint32_t *)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE, &done));

    if (error_msg != NULL) {
        zemu_log(error_msg);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Set the length of the response
    action_addrResponseLen = *tx;

    if (requireConfirmation) {
        view_review_init(tx_getItem, tx_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    THROW(APDU_CODE_OK);
}


__Z_INLINE void handleSignEthTx(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleSignEthTx\n");

    tx_eth_tx();

    bool done = false;
    // cast to integer pointer, because app-ethereum expects them as plain pointers
    parser_error_t err = rs_eth_handle((uint32_t *)flags, (uint32_t *)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE, &done);

    const char *error_msg = tx_err_msg_from_code(err);

    if (err != parser_ok && error_msg != NULL) {
        zemu_log(error_msg);
        const int error_msg_length = strnlen(error_msg, sizeof(G_io_apdu_buffer));
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Wait for all transaction data to be processed
    if (!done) {
        THROW(APDU_CODE_OK);
    }


    view_review_init(tx_getItem, tx_getNumItems, app_sign_eth);

    view_review_show(REVIEW_TXN);

    *flags |= IO_ASYNCH_REPLY;
}


#if defined(FEATURE_ETH)
__Z_INLINE void handle_eip712(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    // Cast volatile pointers to plain pointers due to app-ethereum implementations that takes 
    // them as plain pointers.
    handle_eth_apdu((uint32_t*)flags, (uint32_t*)tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}
#endif

__Z_INLINE void eth_dispatch(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("ETH Dispatch\n");

    switch (G_io_apdu_buffer[OFFSET_INS]) {
#if defined(FEATURE_ETH)
        case INS_SIGN_EIP_712_MESSAGE:
            handle_eip712(flags, tx, rx);
            break;
        case INS_EIP712_STRUCT_DEF:
            handle_eip712(flags, tx, rx);
            break;
        case INS_EIP712_STRUCT_IMPL:
            handle_eip712(flags, tx, rx);
            break;
        case INS_EIP712_FILTERING:
            handle_eip712(flags, tx, rx);
            break;
#endif
        case INS_ETH_GET_APP_CONFIGURATION: {
            CHECK_PIN_VALIDATED()
            handleEthConfig(flags, tx, rx);
            break;
        }

        case INS_PROVIDE_NFT_INFORMATION: {
            CHECK_PIN_VALIDATED()
            handleNftInfo(flags, tx, rx);
            break;
        }

        case INS_SET_PLUGIN: {
            CHECK_PIN_VALIDATED()
            handleSetPlugin(flags, tx, rx);
            break;
        }

        case INS_ETH_PROVIDE_ERC20: {
            CHECK_PIN_VALIDATED()
            handleProvideErc20(flags, tx, rx);
            break;
        }

        case INS_ETH_SIGN: {
            CHECK_PIN_VALIDATED()
            handleSignEthTx(flags, tx, rx);
            break;
        }

        case INS_SIGN_ETH_MSG: {
            CHECK_PIN_VALIDATED()
            handleSignEthMsg(flags, tx, rx);
            break;
        }

        case INS_ETH_GET_PUBLIC_KEY: {
            CHECK_PIN_VALIDATED()
            handleGetAddrEth(flags, tx, rx);
            break;
        }

        default: {
            zemu_log("unknown_eth_instruction***\n");
            THROW(APDU_CODE_INS_NOT_SUPPORTED);
        }
    }
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;
    zemu_log("handleApdu\n");

    BEGIN_TRY {
        TRY {

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            ZEMU_LOGF(50, "CLA: %x\n", G_io_apdu_buffer[OFFSET_CLA]);

            // redicerc this apdu to be dispatched by our avalanche dispatcher, 
            // otherwise use ethereum dispatcher.
            if (G_io_apdu_buffer[OFFSET_CLA] == AVX_CLA) {
                return avax_dispatch(flags, tx, rx);
            } else if (G_io_apdu_buffer[OFFSET_CLA] == ETH_CLA) {
                return eth_dispatch(flags, tx, rx);
            } else {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
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
