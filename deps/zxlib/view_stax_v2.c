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

#include "bolos_target.h"

#if defined(TARGET_STAX)

#include "app_mode.h"
#include "nbgl_use_case.h"
#include "ux.h"
#include "view_internal.h"

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

void rs_h_reject(unsigned int);
bool rs_transaction_screen(uint8_t, nbgl_pageContent_t *);

void app_quit(void) { os_sched_exit(-1); }

//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////

/********* CRAPOLINES *************/

// TODO
void crapoline_ux_wait() {}

// TODO
void crapoline_ux_flow_init_idle_flow_toggle_expert() {}

// TODO
void crapoline_ux_show_review() {}

// TODO
void crapoline_ux_show_error() {}

void crapoline_home() {
  nbgl_useCaseHome(MENU_MAIN_APP_LINE1, NULL, BACKEND_LAZY.items[0].title,
                   false, NULL /* TODO settings screen */, app_quit);
}

void crapoline_show_confirmation(nbgl_pageContent_t *content) {
  content->type = INFO_LONG_PRESS;
  /* content->infoLongPress.icon = &C_badge_transaction_56; */
  content->infoLongPress.icon = NULL;
  content->infoLongPress.text = APPROVE_LABEL;
  content->infoLongPress.longPressText = "Hold to approve";
}

void crapoline_show_items(nbgl_pageContent_t *content, uint8_t nbPairs) {
#define NBGL_PAIR(backend, idx)                                                \
  pairs[idx] = (nbgl_layoutTagValue_t) {                                       \
    .item = (backend.items[idx]).title, .value = (backend.items[idx]).message  \
  }

  static nbgl_layoutTagValue_t pairs[MAX_ITEMS];
  NBGL_PAIR(BACKEND_LAZY, 0);
  NBGL_PAIR(BACKEND_LAZY, 1);
  NBGL_PAIR(BACKEND_LAZY, 2);
  NBGL_PAIR(BACKEND_LAZY, 3);

  content->type = TAG_VALUE_LIST;
  content->tagValueList.pairs = pairs;
  content->tagValueList.wrapping = false;
  content->tagValueList.nbMaxLinesForValue = MAX_LINES_PER_FIELD;
  content->tagValueList.nbPairs = nbPairs;
}

/********* NBGL Specific *************/

void crapoline_useCaseReviewStart(char *title, char *subtitle,
                                  nbgl_callback_t continuation,
                                  nbgl_callback_t reject) {
  nbgl_useCaseReviewStart(NULL, title, subtitle, REJECT_LABEL, continuation,
                          reject);
}

void crapoline_useCaseRegularReview(uint8_t initPage, uint8_t nbPages) {
  nbgl_useCaseRegularReview(initPage, nbPages, REJECT_LABEL,
                            /* button callback */ NULL, rs_transaction_screen,
                            rs_h_reject);
}

#endif
