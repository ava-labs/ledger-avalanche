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
#include "rslib.h"
#include <os.h>
#include <os_io_seproxyhal.h>

#if defined(HAVE_BTC_INTEGRATION)
#include "globals.h"
#include "handler.h"
#else
#include "ux.h"
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#if !defined(HAVE_BTC_INTEGRATION)
unsigned char io_event(unsigned char channel) {
  switch (G_io_seproxyhal_spi_buffer[0]) {
  case SEPROXYHAL_TAG_FINGER_EVENT: //
    UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
    break;

  case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
#ifdef HAVE_BAGL
    UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif
    break;

  case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
    if (!UX_DISPLAYED())
      UX_DISPLAYED_EVENT();
#endif
    break;

  case SEPROXYHAL_TAG_TICKER_EVENT: { //
    UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
      if (UX_ALLOWED) {
        UX_REDISPLAY();
      }
    });
    break;
  }

    // unknown events are acknowledged
  default:
    UX_DEFAULT_EVENT();
    break;
  }
  if (!io_seproxyhal_spi_is_status_sent()) {
    io_seproxyhal_general_status();
  }
  return 1; // DO NOT reset the current APDU transport
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
  switch (channel & ~(IO_FLAGS)) {
  case CHANNEL_KEYBOARD:
    break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
  case CHANNEL_SPI:
    if (tx_len) {
      io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

      if (channel & IO_RESET_AFTER_REPLIED) {
        reset();
      }
      return 0; // nothing received from the master so far (it's a tx
                // transaction)
    } else {
      return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer),
                                    0);
    }

  default:
    THROW(INVALID_PARAMETER);
  }
  return 0;
}
#endif

void io_app_init() {
  io_seproxyhal_init();
  USB_power(0);
  USB_power(1);

#ifdef TARGET_NANOX
  // grab the current plane mode setting
  G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // TARGET_NANOX

#ifdef HAVE_BLE
  // Enable Bluetooth
  BLE_power(0, NULL);
  BLE_power(1, "Nano X");
#endif // HAVE_BLE
}

__attribute__((section(".boot"))) int main(void) {
  // exit critical section
  __asm volatile("cpsie i");
  os_boot();
  view_init();

  volatile uint8_t app_init_done = 0;
  volatile uint32_t rx = 0, tx = 0, flags = 0;
  volatile uint16_t sw = 0;
  zemu_log_stack("main");
#if defined(HAVE_BTC_INTEGRATION)
  initialize_app_globals();
  btc_state_reset();
#endif /* ifndef TARGET_NANOS */

  for (;;) {
#if defined(HAVE_BTC_INTEGRATION)
    // Reset length of APDU response
    G_output_len = 0;
#endif

    BEGIN_TRY {
      TRY {
        if (!app_init_done) {
          io_app_init();
          view_idle_show(0, MENU_MAIN_APP_LINE2);
          app_init_done = 1;
          check_canary();
        }

        rx = tx;
        tx = 0;

        rx = io_exchange(CHANNEL_APDU | flags, rx);
        flags = 0;
        check_canary();

#if !defined(HAVE_BTC_INTEGRATION)
        rs_handle_apdu(&flags, &tx, rx, G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
#else
        if (G_io_apdu_buffer[OFFSET_CLA] == CLA_APP ||
            G_io_apdu_buffer[OFFSET_CLA] == CLA_FRAMEWORK) {
          // call btc handler
          handle_btc_apdu(&flags, &tx, rx, G_io_apdu_buffer,
                          IO_APDU_BUFFER_SIZE);
        } else {
          rs_handle_apdu(&flags, &tx, rx, G_io_apdu_buffer,
                         IO_APDU_BUFFER_SIZE);
        }
#endif

        check_canary();
      }
      CATCH(EXCEPTION_IO_RESET) {
        // reset IO and UX before continuing
        io_app_init();
        view_idle_show(0, MENU_MAIN_APP_LINE2);
        continue;
      }
      CATCH_OTHER(e) {
        if (!app_init_done) {
          switch (e & 0xF000) {
          case 0x6000:
          case 0x9000:
            sw = e;
            break;
          default:
            sw = 0x6800 | (e & 0x7FF);
            break;
          }
          G_io_apdu_buffer[tx] = sw >> 8;
          G_io_apdu_buffer[tx + 1] = sw;
          tx += 2;
        } else {
          // Exception
          G_io_apdu_buffer[0] = e >> 8;
          G_io_apdu_buffer[1] = e;

          // ExecutionError
          G_io_apdu_buffer[2] = 0x64;
          G_io_apdu_buffer[3] = 0x00;
          tx = 4;
        }
      }
      FINALLY {}
    }
    END_TRY;
  }
}
