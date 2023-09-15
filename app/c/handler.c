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

#include "bolos_target.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#include "globals.h"
// #include "io.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"
#include "sw.h"
#include "ui/menu.h"

#include "debug-helpers/debug.h"

#include "commands.h"
#include "handler/handlers.h"

#include "common/wallet.h"

#include "swap/handle_check_address.h"
#include "swap/handle_get_printable_amount.h"
#include "swap/handle_swap_sign_transaction.h"
#include "swap/swap_globals.h"
#include "swap/swap_lib_calls.h"

#include "handler.h"

dispatcher_context_t G_dispatcher_context;

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_EXTENDED_PUBKEY,
        .handler = (command_handler_t)handler_get_extended_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_PSBT,
        .handler = (command_handler_t)handler_sign_psbt
    },
    {
        .cla = CLA_APP,
        .ins = GET_MASTER_FINGERPRINT,
        .handler = (command_handler_t)handler_get_master_fingerprint
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_MESSAGE,
        .handler = (command_handler_t)handler_sign_message
    },
};
// clang-format on

void btc_state_reset() {
  // Reset dispatcher state
  explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));
}

void handle_btc_apdu(volatile uint32_t *flags, volatile uint32_t *tx,
                     uint32_t rx, const uint8_t *buffer, uint16_t bufferLen) {
  UNUSED(flags);
  UNUSED(tx);
  // Structured APDU command
  command_t cmd;

  // Reset structured APDU command
  memset(&cmd, 0, sizeof(cmd));

  // Parse APDU command from G_io_apdu_buffer
  if (!apdu_parser(&cmd, G_io_apdu_buffer, rx)) {
    io_send_sw(SW_WRONG_DATA_LENGTH);
    return;
  }

  // Dispatch structured APDU command to handler
  apdu_dispatcher(COMMAND_DESCRIPTORS,
                  sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                  ui_menu_main, &cmd);
}

void initialize_app_globals() {
  io_reset_timeouts();

  // We only zero the called_from_swap and should_exit fields and not the entire
  // G_swap_state, as we need the globals initialization to happen _after_
  // calling copy_transaction_parameters when processing a SIGN_TRANSACTION
  // request from the swap app (which initializes the other fields of
  // G_swap_state).
  G_swap_state.called_from_swap = false;
  G_swap_state.should_exit = false;
}
#endif
