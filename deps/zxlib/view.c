/*******************************************************************************
 *   (c) 2018, 2019 Zondax GmbH
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

#include "view.h"
#include "coin.h"
#include "view_internal.h"

#include "actions.h"
#include "app_mode.h"

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
#include "bagl.h"
#include "ux.h"
#include "view_templates.h"
#endif

#include "zxerror.h"
#include "zxmacros.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

///////////////////////////////////
// General

#if !defined(HAVE_BTC_INTEGRATION) && !defined(TARGET_STAX)
void io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}
#endif
void view_init(void) {
#if defined(BLIND_SIGN_TOGGLE)
  blind_sign.toggle = false;
  h_blind_sign_update();
#endif
  view_init_impl((const char *)MENU_MAIN_APP_LINE2);
  UX_INIT();
}

void view_idle_show(uint8_t item_idx, const char *statusString) {
  view_idle_show_impl(item_idx, statusString);
}
