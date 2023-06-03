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
#include "coin.h"

#if defined(TARGET_STAX)

#include "app_mode.h"
#include "nbgl_use_case.h"
#include "ux.h"
#include "view_internal.h"

#define APPROVE_LABEL_STAX "Sign transaction?"
#define REJECT_LABEL_STAX "Reject transaction"
#define CANCEL_LABEL "Cancel"
#define HOLD_TO_APPROVE_MSG "Hold to sign"

static const char *const INFO_KEYS[] = {"Version", "Developed by", "Website",
                                        "License"};
static const char *const INFO_VALUES[] = {APPVERSION, "Zondax AG",
                                          "https://zondax.ch", "Apache 2.0"};

typedef enum {
  EXPERT_MODE_TOKEN = FIRST_USER_TOKEN,
#ifdef BLIND_SIGN_TOGGLE
  BLING_SIGN_TOKEN,
#endif
} config_token_e;

ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

/* Functions from rust */
void rs_h_reject(unsigned int);
bool rs_update_static_item(uint8_t, uint8_t);
void rs_action_callback(bool);
bool rs_h_expert();
bool rs_h_toggle_expert();

#ifdef BLIND_SIGN_TOGGLE
blind_sign_toggle_t blind_sign;
bool h_blind_sign();
void h_toggle_blind_sign();
#endif

/* Other functions */
void settings_toggle_cb(int, uint8_t);
bool settings_screen_cb(uint8_t, nbgl_pageContent_t *);
void settings_screen();
void crapoline_home();
static nbgl_layoutTagValue_t *update_static_items(uint8_t);

/*** IMPLS ****/

#ifdef BLIND_SIGN_TOGGLE
bool h_blind_sign() { return blind_sign.toggle; }
void h_toggle_blind_sign() { blind_sign.toggle = !blind_sign.toggle; }
#endif

void app_quit(void) { os_sched_exit(-1); }

static nbgl_layoutSwitch_t settings[4];
void settings_toggle_cb(int token, uint8_t idx) {
  switch (token) {
  case EXPERT_MODE_TOKEN:
    rs_h_toggle_expert();
    break;

#ifdef BLIND_SIGN_TOGGLE
  case BLIND_SIGN_TOKEN:
    h_toggle_blind_sign();
    break;
#endif

  default:
    break;
  }
}

bool settings_screen_cb(uint8_t page, nbgl_pageContent_t *content) {
  switch (page) {
  case 0: {
    content->type = INFOS_LIST;
    content->infosList.nbInfos = sizeof(INFO_KEYS) / sizeof(INFO_KEYS[0]);
    content->infosList.infoContents = INFO_VALUES;
    content->infosList.infoTypes = INFO_KEYS;
    break;
  }
  case 1: {
    content->type = SWITCHES_LIST;
    content->switchesList.nbSwitches = 1;
    content->switchesList.switches = settings;

    settings[0].initState = rs_h_expert();
    settings[0].text = "Expert mode:";
    settings[0].tuneId = TUNE_TAP_CASUAL;
    settings[0].token = EXPERT_MODE_TOKEN;

#ifdef BLIND_SIGN_TOGGLE
    settings[1].initState = h_blind_sign();
    settings[1].text = "Blind sign mode:";
    settings[1].tuneId = TUNE_TAP_CASUAL;
    settings[1].token = BLIND_SIGN_TOKEN;
    context->switchesList.nbSwitches++;
#endif
    break;
  }
  default:
    return false;
  }

  return true;
}

void settings_screen() {
  nbgl_useCaseSettings(MENU_MAIN_APP_LINE1, 0, 2, false, crapoline_home,
                       settings_screen_cb, settings_toggle_cb);
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
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
//////////////////////////
/****** CRAPOLINES ******** */

void crapoline_home() {
  nbgl_useCaseHome(MENU_MAIN_APP_LINE1, NULL,
                   (const char *)BACKEND_LAZY.items[0].title, true,
                   settings_screen, app_quit);
}

/********* NBGL Specific *************/
void crapoline_useCaseReviewStart(char *, char *, nbgl_callback_t,
                                  nbgl_callback_t);
void crapoline_useCaseStaticReview(uint8_t);
void crapoline_useCaseAddressConfirmationExt(uint8_t);

/*** IMPLS ****/
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
