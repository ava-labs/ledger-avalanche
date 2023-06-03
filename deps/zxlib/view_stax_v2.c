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

#define APPROVE_LABEL_STAX "Sign transaction?"
#define REJECT_LABEL_STAX "Reject transaction"
#define CANCEL_LABEL "Cancel"
#define HOLD_TO_APPROVE_MSG "Hold to sign"

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

void rs_h_reject(unsigned int);
bool rs_update_static_item(uint8_t, uint8_t);
void rs_action_callback(bool);

void app_quit(void) { os_sched_exit(-1); }

//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////

/********* CRAPOLINES *************/

void crapoline_home() {
  nbgl_useCaseHome(MENU_MAIN_APP_LINE1, NULL,
                   (const char *)BACKEND_LAZY.items[0].title, false,
                   NULL /* TODO settings screen */, app_quit);
}

static nbgl_layoutTagValue_t pairs[NB_MAX_DISPLAYED_PAIRS_IN_REVIEW];
static nbgl_layoutTagValue_t *update_static_items(uint8_t index) {
  uint8_t internalIndex = index % MAX_ITEMS;

  if (!rs_update_static_item(index, internalIndex)) {
    return NULL;
  }

  pairs[0] = (nbgl_layoutTagValue_t){
      .item = (const char *)BACKEND_LAZY.items[internalIndex].title,
      .value = (const char *)BACKEND_LAZY.items[internalIndex].message};

  return &pairs[0];
}

/********* NBGL Specific *************/

void crapoline_useCaseReviewStart(char *title, char *subtitle,
                                  nbgl_callback_t continuation,
                                  nbgl_callback_t reject) {
  nbgl_useCaseReviewStart(NULL /* &C_icon_stax_64 */, title, subtitle,
                          REJECT_LABEL_STAX, continuation, reject);
}

static nbgl_layoutTagValueList_t pairList;
static nbgl_pageInfoLongPress_t infoLongPress;
void crapoline_useCaseStaticReview(uint8_t nbPages) {
  /* infoLongPress.icon = &C_icon_stax_64; */
  infoLongPress.icon = NULL;
  infoLongPress.text = APPROVE_LABEL_STAX;
  infoLongPress.longPressText = HOLD_TO_APPROVE_MSG;

  pairList.nbMaxLinesForValue = NB_MAX_LINES_IN_REVIEW;
  pairList.nbPairs = nbPages;
  pairList.pairs = NULL; // make use of callback
  pairList.callback = update_static_items;
  pairList.startIndex = 0;

  nbgl_useCaseStaticReview(&pairList, &infoLongPress, REJECT_LABEL_STAX,
                           rs_action_callback);
}

void crapoline_useCaseAddressConfirmationExt(uint8_t nbPages) {
  nbgl_layoutTagValueList_t *extraPagesPtr = NULL;
  if (nbPages > 1) {
    nbPages--;
    for (uint8_t idx = 0; idx < nbPages; idx++) {
      pairs[idx].item = (const char *)BACKEND_LAZY.items[idx + 1].title;
      pairs[idx].value = (const char *)BACKEND_LAZY.items[idx + 1].message;
    }

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = nbPages;
    pairList.pairs = pairs;

    extraPagesPtr = &pairList;
  }

  nbgl_useCaseAddressConfirmationExt(
      (const char *)BACKEND_LAZY.items[0].message, rs_action_callback,
      extraPagesPtr);
}
#endif
