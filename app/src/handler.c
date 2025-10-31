/*******************************************************************************
 *   (c) 2016 Ledger
 *   (c) 2018-2023 Zondax AG
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

#if defined(FEATURE_ETH)
// #include "globals.h"
// #include "io.h"
#include "apdu_constants.h"
#include "commands_712.h"
#include "common_ui.h"
#include "common_utils.h"
#include "cx_errors.h"
#include "glyphs.h"
#include "handle_check_address.h"
#include "handle_get_printable_amount.h"
#include "handle_swap_sign_transaction.h"
#include "os_io_seproxyhal.h"
#include "shared_context.h"
#include "swap_lib_calls.h"
// #include "challenge.h"
// #include "domain_name.h"
#include "lib_standard_app/crypto_helpers.h"
// not use in master branch
// #include "manage_asset_info.h"

#include "handler.h"

// dispatcher_context_t G_dispatcher_context;

uint32_t set_result_get_publicKey(void);
void finalizeParsing(bool);

// Variables bellow are used by app-ethereum app
// to handle/manage stages during parsing and signing
tmpCtx_t tmpCtx;
txContext_t txContext;
tmpContent_t tmpContent;
dataContext_t dataContext;
strings_t strings;
cx_sha3_t global_sha3;

uint8_t appState;
uint16_t apdu_response_code;
bool G_called_from_swap;
bool G_swap_response_ready;
pluginType_t pluginType;

#ifdef HAVE_ETH2
uint32_t eth2WithdrawalIndex;
// #include "withdrawal_index.h"
#endif

#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

const internalStorage_t N_storage_real;

#ifdef HAVE_NBGL
caller_app_t *caller_app = NULL;
#endif

const chain_config_t *chainConfig = NULL;
chain_config_t config;

// This function is only present in master branch
// was moved/removed in develop branch.
// to keep in mind when develop gets merged into master
// later.
void format_signature_out(const uint8_t *signature) {
    memset(G_io_apdu_buffer + 1, 0x00, 64);
    uint8_t offset = 1;
    uint8_t xoffset = 4;  // point to r value
    // copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
    offset += 32;
    xoffset += xlength + 2;  // move over rvalue and TagLEn
    // copy s value
    xlength = signature[xoffset - 1];
    if (xlength == 33) {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
}

void reset_app_context() {
    appState = APP_STATE_IDLE;
    G_called_from_swap = false;
    G_swap_response_ready = false;
    pluginType = OLD_INTERNAL;
#ifdef HAVE_ETH2
    eth2WithdrawalIndex = 0;
#endif
    memset((uint8_t *)&tmpCtx, 0, sizeof(tmpCtx));
    memset((uint8_t *)&txContext, 0, sizeof(txContext));
    memset((uint8_t *)&tmpContent, 0, sizeof(tmpContent));
}

void io_seproxyhal_send_status(uint32_t sw) {
    G_io_apdu_buffer[0] = ((sw >> 8) & 0xff);
    G_io_apdu_buffer[1] = (sw & 0xff);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

// clang-format on

const uint8_t *parseBip32(const uint8_t *dataBuffer, uint8_t *dataLength, bip32_path_t *bip32) {
    if (*dataLength < 1) {
        PRINTF("Invalid data\n");
        return NULL;
    }

    bip32->length = *dataBuffer;

    if (bip32->length < 0x1 || bip32->length > MAX_BIP32_PATH) {
        PRINTF("Invalid bip32\n");
        return NULL;
    }

    dataBuffer++;
    (*dataLength)--;

    if (*dataLength < sizeof(uint32_t) * (bip32->length)) {
        PRINTF("Invalid data\n");
        return NULL;
    }

    for (uint8_t i = 0; i < bip32->length; i++) {
        bip32->path[i] = U4BE(dataBuffer, 0);
        dataBuffer += sizeof(uint32_t);
        *dataLength -= sizeof(uint32_t);
    }

    return dataBuffer;
}

void init_coin_config(chain_config_t *coin_config) {
    memset(coin_config, 0, sizeof(chain_config_t));
    strcpy(coin_config->coinName, CHAINID_COINNAME);
    coin_config->chainId = CHAIN_ID;
}

/**
 * Handles incoming APDU commands for Ethereum operations.
 *
 * This function processes a variety of Ethereum-related operations including key management,
 * signing transactions, and token information provisioning. It is designed to respond to a set
 * of predefined APDU instructions and manage their execution securely within a hardware wallet or similar environment.
 *
 * @param flags A pointer to the volatile uint32_t flags used to manage APDU response behaviors.
 * @param tx A pointer to the volatile uint32_t transaction context, indicating the length of the response.
 * @param rx The length of the received APDU data.
 * @param buffer A pointer to the data buffer containing the APDU commands.
 * @param bufferLen The total length of the data buffer.
 *
 * @note This function sets the blockchain configuration on the first call and logs each operation.
 *       It includes extensive error handling to gracefully manage exceptions and reset the context as needed.
 */
void handle_eth_apdu(__Z_UNUSED uint32_t *flags, uint32_t *tx, __Z_UNUSED uint32_t rx, uint8_t *buffer,
                     __Z_UNUSED uint16_t bufferLen) {
    unsigned short sw = 0;

    // This is the best place to put this,
    // and by checking to NULL we ensure that it is set once,
    // after the first call to this function
    if (chainConfig == NULL) {
        init_coin_config(&config);
        chainConfig = &config;
    }

    BEGIN_TRY {
        TRY {
            if (buffer[OFFSET_CLA] != CLA) {
                THROW(0x6E00);
            }

            switch (buffer[OFFSET_INS]) {
                // From app-ethereum only EIP-712 functionality is used
                // we decided to keep below cases for future use.
                // case INS_GET_PUBLIC_KEY:
                //
                //     forget_known_assets();
                //     handleGetPublicKey(buffer[OFFSET_P1],
                //                        buffer[OFFSET_P2],
                //                        buffer + OFFSET_CDATA,
                //                        buffer[OFFSET_LC],
                //                        flags,
                //                        tx);
                //     break;

                // case INS_PROVIDE_ERC20_TOKEN_INFORMATION:
                //     handleProvideErc20TokenInformation(buffer[OFFSET_P1],
                //                                        buffer[OFFSET_P2],
                //                                        buffer + OFFSET_CDATA,
                //                                        buffer[OFFSET_LC],
                //                                        flags,
                //                                        tx);
                //     break;

#ifdef HAVE_NFT_SUPPORT
                // case INS_PROVIDE_NFT_INFORMATION:
                //     handleProvideNFTInformation(buffer[OFFSET_P1],
                //                                 buffer[OFFSET_P2],
                //                                 buffer + OFFSET_CDATA,
                //                                 buffer[OFFSET_LC],
                //                                 flags,
                //                                 tx);
                //     break;
#endif  // HAVE_NFT_SUPPORT

                    // case INS_SET_EXTERNAL_PLUGIN:
                    //     handleSetExternalPlugin(buffer[OFFSET_P1],
                    //                             buffer[OFFSET_P2],
                    //                             buffer + OFFSET_CDATA,
                    //                             buffer[OFFSET_LC],
                    //                             flags,
                    //                             tx);
                    //     break;

                    // case INS_SET_PLUGIN:
                    //     handleSetPlugin(buffer[OFFSET_P1],
                    //                     buffer[OFFSET_P2],
                    //                     buffer + OFFSET_CDATA,
                    //                     buffer[OFFSET_LC],
                    //                     flags,
                    //                     tx);
                    //     break;

                    // case INS_PERFORM_PRIVACY_OPERATION:
                    //     handlePerformPrivacyOperation(buffer[OFFSET_P1],
                    //                                   buffer[OFFSET_P2],
                    //                                   buffer + OFFSET_CDATA,
                    //                                   buffer[OFFSET_LC],
                    //                                   flags,
                    //                                   tx);
                    //     break;

                    // case INS_SIGN:
                    //     handleSign(buffer[OFFSET_P1],
                    //                buffer[OFFSET_P2],
                    //                buffer + OFFSET_CDATA,
                    //                buffer[OFFSET_LC],
                    //                flags,
                    //                tx);
                    //     break;
                    //
                    // case INS_GET_APP_CONFIGURATION:
                    //     handleGetAppConfiguration(buffer[OFFSET_P1],
                    //                               buffer[OFFSET_P2],
                    //                               buffer + OFFSET_CDATA,
                    //                               buffer[OFFSET_LC],
                    //                               flags,
                    //                               tx);
                    //     break;
                    //
                    // case INS_SIGN_PERSONAL_MESSAGE:
                    //     forget_known_assets();
                    //     *flags |= IO_ASYNCH_REPLY;
                    //     if (!handleSignPersonalMessage(buffer[OFFSET_P1],
                    //                                    buffer[OFFSET_P2],
                    //                                    buffer + OFFSET_CDATA,
                    //                                    buffer[OFFSET_LC])) {
                    //         reset_app_context();
                    //     }
                    //     break;

                case INS_SIGN_EIP_712_MESSAGE:
                    switch (buffer[OFFSET_P2]) {
                        case P2_EIP712_LEGACY_IMPLEM:
                            // use in develop but not present in master
                            // forget_known_assets();
                            // use in master instead of the above
                            handleSignEIP712Message_v0(buffer[OFFSET_P1], buffer[OFFSET_P2], buffer + OFFSET_CDATA,
                                                       buffer[OFFSET_LC], flags, tx);
                            break;
#ifdef HAVE_EIP712_FULL_SUPPORT
                        case P2_EIP712_FULL_IMPLEM:
                            *flags |= IO_ASYNCH_REPLY;
                            handle_eip712_sign(buffer);
                            break;
#endif  // HAVE_EIP712_FULL_SUPPORT
                        default:
                            THROW(APDU_RESPONSE_INVALID_P1_P2);
                    }
                    break;

                    // #ifdef HAVE_ETH2
                    //
                    //                 case INS_GET_ETH2_PUBLIC_KEY:
                    //                     forget_known_assets();
                    //                     handleGetEth2PublicKey(buffer[OFFSET_P1],
                    //                                            buffer[OFFSET_P2],
                    //                                            buffer + OFFSET_CDATA,
                    //                                            buffer[OFFSET_LC],
                    //                                            flags,
                    //                                            tx);
                    //                     break;
                    //
                    //                 case INS_SET_ETH2_WITHDRAWAL_INDEX:
                    //                     handleSetEth2WithdrawalIndex(buffer[OFFSET_P1],
                    //                                                  buffer[OFFSET_P2],
                    //                                                  buffer + OFFSET_CDATA,
                    //                                                  buffer[OFFSET_LC],
                    //                                                  flags,
                    //                                                  tx);
                    //                     break;
                    //
                    // #endif

#ifdef HAVE_EIP712_FULL_SUPPORT
                case INS_EIP712_STRUCT_DEF:
                    *flags |= IO_ASYNCH_REPLY;
                    handle_eip712_struct_def(buffer);
                    break;

                case INS_EIP712_STRUCT_IMPL:
                    *flags |= IO_ASYNCH_REPLY;
                    handle_eip712_struct_impl(G_io_apdu_buffer);
                    break;

                case INS_EIP712_FILTERING:
                    *flags |= IO_ASYNCH_REPLY;
                    handle_eip712_filtering(buffer);
                    break;
#endif  // HAVE_EIP712_FULL_SUPPORT

                    // #ifdef HAVE_DOMAIN_NAME
                    //                 case INS_ENS_GET_CHALLENGE:
                    //                     handle_get_challenge();
                    //                     break;
                    //
                    //                 case INS_ENS_PROVIDE_INFO:
                    //                     handle_provide_domain_name(buffer[OFFSET_P1],
                    //                                                buffer[OFFSET_P2],
                    //                                                buffer + OFFSET_CDATA,
                    //                                                buffer[OFFSET_LC]);
                    //                     break;
                    // #endif  // HAVE_DOMAIN_NAME

                default:
                    THROW(0x6D00);
                    break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e) {
            bool quit_now = G_called_from_swap && G_swap_response_ready;
            switch (e & 0xF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    reset_app_context();
                    break;
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    reset_app_context();
                    break;
            }
            // Unexpected exception => report
            buffer[*tx] = sw >> 8;
            buffer[*tx + 1] = sw;
            *tx += 2;

            // If we are in swap mode and have validated a TX, we send it and immediately quit
            if (quit_now) {
                if (io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, *tx) == 0) {
                    // In case of success, the apdu is sent immediately and eth exits
                    // Reaching this code means we encountered an error
                    finalize_exchange_sign_transaction(false);
                } else {
                    PRINTF("Unrecoverable\n");
                    os_sched_exit(-1);
                }
            }
        }
        FINALLY {}
    }
    END_TRY;
}

#endif
