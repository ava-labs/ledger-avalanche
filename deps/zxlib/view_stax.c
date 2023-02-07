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

#include "view_internal.h"
#include "ux.h"
#include "app_mode.h"
#include "nbgl_use_case.h"

#include "nbgl_page.h"

#ifdef APP_SECRET_MODE_ENABLED
zxerr_t secret_enabled();
#endif

#ifdef APP_ACCOUNT_MODE_ENABLED
zxerr_t account_enabled();
#endif

#ifdef SHORTCUT_MODE_ENABLED
zxerr_t shortcut_enabled();
#endif


ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
extern unsigned int review_type;

static nbgl_layoutTagValue_t pairs[FIELDS_PER_PAGE];
static nbgl_layoutTagValueList_t pairList;

static nbgl_layoutSwitch_t settings[4];

static uint8_t total_pages;


typedef enum {
    EXPERT_MODE = 0,
#ifdef APP_ACCOUNT_MODE_ENABLED
    ACCOUNT_MODE,
#endif
#ifdef SHORTCUT_MODE_ENABLED
    SHORTCUT_MODE,
#endif
#ifdef APP_SECRET_MODE_ENABLED
    SECRET_MODE,
#endif
} settings_list_e;


typedef enum {
  EXPERT_MODE_TOKEN = FIRST_USER_TOKEN,
  ACCOUNT_MODE_TOKEN,
  SHORTCUT_MODE_TOKEN,
  SECRET_MODE_TOKEN,
} config_token_e;

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

void h_reject_internal(void) {
    h_reject(review_type);
}

static void view_idle_show_impl_callback() {
    view_idle_show_impl(0, NULL);
}

static const char* const INFO_KEYS[] = {"Version", "Developed by:", "Website:", "License:"};
static const char* const INFO_VALUES[] = {APPVERSION, "Zondax AG", "zondax.ch", "Apache 2.0"};

static const char* txn_choice_message = "Reject transaction?";
static const char* add_choice_message = "Reject address?";
static const char* ui_choice_message = "Reject configuration?";

static void h_expert_toggle() {
    app_mode_set_expert(!app_mode_expert());
}

static void confirm_callback(bool confirm) {
    confirm ? h_approve(review_type) : h_reject(review_type);
}
static void reject_confirmation_callback(bool reject) {
    if (reject) {
        confirm_callback(false);
    }
}

static void confirm_transaction_callback(bool confirm) {
    char* message = NULL;
    if (confirm) {
        // nbgl_useCaseStatus("Approved", true, view_idle_show_impl_callback);
        confirm_callback(confirm);
    } else {
        switch (review_type)
        {
        case REVIEW_UI:
            message = PIC(ui_choice_message);
            break;

        case REVIEW_ADDRESS:
            message = PIC(add_choice_message);
            break;

        case REVIEW_TXN:
            message = PIC(txn_choice_message);
            break;

        default:
            //ZEMU_LOGF(50, "Error unrecognize review option\n")
            view_error_show();
            return;
        }
        if (message == NULL) {
            view_error_show();
            return;
        }

        nbgl_useCaseChoice(&C_Eye_48px,
                           message,
                           NULL,
                           "Yes, reject",
                           "Go back",
                           reject_confirmation_callback);
    }
}

static void confirm_setting(bool confirm) {
    if (confirm && BACKEND_LAZY.viewfuncAccept != NULL) {
        BACKEND_LAZY.viewfuncAccept();
        return;
    }
    confirm_callback(confirm);
}

void view_error_show() {
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];
    snprintf(BACKEND_LAZY.key, MAX_CHARS_PER_KEY_LINE, "ERROR");
    snprintf(BACKEND_LAZY.message, MAX_CHARS_PER_VALUE1_LINE, "SHOWING DATA");
    view_error_show_impl();
}

void view_error_show_impl() {
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];
    const zxerr_t err = h_review_update_data();
    if (err != zxerr_ok)
    {
        //ZEMU_LOGF(50, "Config screen error\n")
        view_idle_show(0, NULL);
    }

    nbgl_useCaseChoice(&C_icon_warning, BACKEND_LAZY.key, BACKEND_LAZY.message, "Ok", NULL, confirm_setting);
}

zxerr_t h_review_update_data() {
    if (BACKEND_LAZY.viewfuncGetNumItems == NULL) {
        //ZEMU_LOGF(50, "h_review_update_data - GetNumItems == NULL\n")
        return zxerr_no_data;
    }
    if (BACKEND_LAZY.viewfuncGetItem == NULL) {
        //ZEMU_LOGF(50, "h_review_update_data - GetItems == NULL\n")
        return zxerr_no_data;
    }

    if (BACKEND_LAZY.viewfuncAccept == NULL) {
        //ZEMU_LOGF(50, "h_review_update_data - Function Accept == NULL\n")
        return zxerr_no_data;
    }

    if (BACKEND_LAZY.key == NULL || BACKEND_LAZY.message == NULL) {
        return zxerr_unknown;
    }

    CHECK_ZXERR(BACKEND_LAZY.viewfuncGetNumItems(&BACKEND_LAZY.itemCount))

    if (BACKEND_LAZY.itemIdx  >= BACKEND_LAZY.itemCount) {
        return zxerr_no_data;
    }

    CHECK_ZXERR(BACKEND_LAZY.viewfuncGetItem(
            BACKEND_LAZY.itemIdx,
            BACKEND_LAZY.key, MAX_CHARS_PER_KEY_LINE,
            BACKEND_LAZY.message, MAX_CHARS_PER_VALUE1_LINE,
            BACKEND_LAZY.pageIdx, &BACKEND_LAZY.pageCount))

    return zxerr_ok;
}

void h_review_update() {
    zxerr_t err = h_review_update_data();
    switch(err) {
        case zxerr_ok:
        case zxerr_no_data:
            break;
        default:
            //ZEMU_LOGF(50, "View error show\n")
            view_error_show();
            break;
    }
}

static bool settings_screen_callback(uint8_t page, nbgl_pageContent_t* content) {
    switch ((uint8_t) page)
    {
        case 0: {
            content->type = INFOS_LIST;
            content->infosList.nbInfos = sizeof(INFO_KEYS)/sizeof(INFO_KEYS[0]);
            content->infosList.infoContents = (const char**) INFO_KEYS;
            content->infosList.infoTypes = (const char**) INFO_VALUES;
            break;
        }

        case 1: {
            // Config
            content->type = SWITCHES_LIST;
            content->switchesList.nbSwitches = 1;
            content->switchesList.switches = settings;

            settings[0].initState = app_mode_expert();
            settings[0].text = "Expert mode";
            settings[0].tuneId = TUNE_TAP_CASUAL;
            settings[0].token = EXPERT_MODE_TOKEN;

#ifdef APP_ACCOUNT_MODE_ENABLED
            if (app_mode_expert() || app_mode_account()) {
                settings[ACCOUNT_MODE].initState = app_mode_account();
                settings[ACCOUNT_MODE].text = "Crowdloan account";
                settings[ACCOUNT_MODE].tuneId = TUNE_TAP_CASUAL;
                settings[ACCOUNT_MODE].token = ACCOUNT_MODE_TOKEN;
                content->switchesList.nbSwitches++;
            }
#endif

#ifdef SHORTCUT_MODE_ENABLED
            if (app_mode_expert() || app_mode_shortcut()) {
                settings[SHORTCUT_MODE].initState = app_mode_shortcut();
                settings[SHORTCUT_MODE].text = "Shortcut mode";
                settings[SHORTCUT_MODE].tuneId = TUNE_TAP_CASUAL;
                settings[SHORTCUT_MODE].token = SHORTCUT_MODE_TOKEN;
                content->switchesList.nbSwitches++;
            }
#endif

#ifdef APP_SECRET_MODE_ENABLED
            if (app_mode_expert() || app_mode_secret()) {
                settings[SECRET_MODE].initState = app_mode_secret();
                settings[SECRET_MODE].text = "Secret mode";
                settings[SECRET_MODE].tuneId = TUNE_TAP_CASUAL;
                settings[SECRET_MODE].token = SECRET_MODE_TOKEN;
                content->switchesList.nbSwitches++;
            }
#endif
            break;
        }

        default:
            //ZEMU_LOGF(50, "Incorrect settings page: %d\n", page)
            return false;
    }

    return true;
}

static void settings_toggle_callback(int token, uint8_t index) {
    switch (token)
    {
        case EXPERT_MODE_TOKEN:
            h_expert_toggle();
            break;

#ifdef APP_ACCOUNT_MODE_ENABLED
        case ACCOUNT_MODE_TOKEN:
            account_enabled();
            break;
#endif

#ifdef SHORTCUT_MODE_ENABLED
        case SHORTCUT_MODE_TOKEN:
            shortcut_enabled();
            break;
#endif

#ifdef APP_SECRET_MODE_ENABLED
        case SECRET_MODE_TOKEN:
            secret_enabled();
            break;
#endif

        default:
            //ZEMU_LOGF(50, "Toggling setting not found\n")
            break;
    }
}

void setting_screen() {
    //Set return button top-left (true) botton-left (false)
    const bool return_button_top_left = true;
    const uint8_t init_page = 0;
    const uint8_t total_pages = 2;
    nbgl_useCaseSettings(MENU_MAIN_APP_LINE1, init_page, total_pages, return_button_top_left,
                        view_idle_show_impl_callback, settings_screen_callback, settings_toggle_callback);
}

void view_idle_show_impl(__Z_UNUSED uint8_t item_idx, char *statusString) {
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    if (statusString == NULL ) {
        snprintf(BACKEND_LAZY.key, MAX_CHARS_PER_KEY_LINE, "%s", MENU_MAIN_APP_LINE2);
#ifdef APP_SECRET_MODE_ENABLED
        if (app_mode_secret()) {
            snprintf(BACKEND_LAZY.key, MAX_CHARS_PER_KEY_LINE, "%s", MENU_MAIN_APP_LINE2_SECRET);
        }
#endif
    } else {
        snprintf(BACKEND_LAZY.key, MAX_CHARS_PER_KEY_LINE, "%s", statusString);
    }

    const bool settings_icon = false;
    nbgl_useCaseHome(MENU_MAIN_APP_LINE1, &C_icon_app, BACKEND_LAZY.key, settings_icon, setting_screen, app_quit);
}

static uint16_t computeTextLines(const char* text) {
    return nbgl_getTextNbLinesInWidth(BAGL_FONT_INTER_REGULAR_32px,
                text,
                SCREEN_WIDTH-2*BORDER_MARGIN,
                false);
}

zxerr_t navigate_pages(uint8_t initialPage, uint8_t finalPage, uint8_t *countedPages) {
    uint8_t pages = 0;
    uint8_t accumLines = 0;
    uint8_t itemsPerPage = 0;
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];

    for (BACKEND_LAZY.itemIdx = 0; BACKEND_LAZY.itemIdx < BACKEND_LAZY.itemCount; BACKEND_LAZY.itemIdx++) {
        if (pages == finalPage) {
            break;
        }

        CHECK_ZXERR(h_review_update_data())
        const uint16_t currentValueLines = computeTextLines(BACKEND_LAZY.message);

        const uint8_t totalLines = accumLines + currentValueLines;
        const bool addItemToCurrentPage =      (totalLines <= 6 && itemsPerPage <= 3)     // Display 6 lines limiting items to 4
                                            || (totalLines <= 7 && itemsPerPage <= 2)     // Display 7 lines limiting items to 3
                                            || (totalLines == 8 && itemsPerPage <= 1);    // Display 8 lines only for 1 or 2 items on screen

        if (addItemToCurrentPage) {
            accumLines = totalLines;
            itemsPerPage++;
        } else {
            // Move item to next page
            accumLines = currentValueLines;
            pages++;
            itemsPerPage = 1;
        }
    }

    // Return counted pages
    if (countedPages != NULL) {
        *countedPages = pages + 1;
    }

    return zxerr_ok;
}

static zxerr_t update_data_page(uint8_t page, uint8_t *elementsPerPage) {
    if (elementsPerPage == NULL) {
        return zxerr_unknown;
    }

    *elementsPerPage = 0;
    uint8_t itemsPerPage = 0;
    uint8_t accumLines = 0;

    // Navigate until current page
    CHECK_ZXERR(navigate_pages(0, page, NULL))

    if (BACKEND_LAZY.itemIdx > 0) {
        BACKEND_LAZY.itemIdx--;
    }

    for (BACKEND_LAZY.itemIdx; BACKEND_LAZY.itemIdx < BACKEND_LAZY.itemCount; BACKEND_LAZY.itemIdx++) {
        if (itemsPerPage >= FIELDS_PER_PAGE) {
            break;
        }
        BACKEND_LAZY.key = BACKEND_LAZY.keys[itemsPerPage];
        BACKEND_LAZY.message = BACKEND_LAZY.messages[itemsPerPage];
        CHECK_ZXERR(h_review_update_data())

        const uint16_t currentValueLines = computeTextLines(BACKEND_LAZY.message);
        const uint8_t totalLines = accumLines + currentValueLines;

        const bool addItemToCurrentPage =      (totalLines <= 6 && itemsPerPage <= 3)     // Display 6 lines limiting items to 4
                                            || (totalLines <= 7 && itemsPerPage <= 2)     // Display 7 lines limiting items to 3
                                            || (totalLines == 8 && itemsPerPage <= 1);    // Display 8 lines only for 1 or 2 items on screen

        if (!addItemToCurrentPage) {
            break;
        }
        accumLines = totalLines;
        itemsPerPage++;
    }

    *elementsPerPage = itemsPerPage;

    return zxerr_ok;
}

static bool transaction_screen_callback(uint8_t page, nbgl_pageContent_t *content) {

    const zxerr_t err = (page == total_pages || page == LAST_PAGE_FOR_REVIEW) ? zxerr_no_data : update_data_page(page, &content->tagValueList.nbPairs);

    switch(err) {
        case zxerr_ok: {
            content->type = TAG_VALUE_LIST;
            content->tagValueList.pairs = pairs;
            content->tagValueList.wrapping = false;
            content->tagValueList.nbMaxLinesForValue = MAX_LINES_PER_FIELD;

            for (uint8_t i = 0; i < content->tagValueList.nbPairs; i++) {
                pairs[i].item = BACKEND_LAZY.keys[i];
                pairs[i].value = BACKEND_LAZY.messages[i];
            }
            break;
        }
        case zxerr_no_data: {
            content->type = INFO_LONG_PRESS;
            content->infoLongPress.icon = &C_badge_transaction_56;
            content->infoLongPress.text = APPROVE_LABEL;
            content->infoLongPress.longPressText = "Hold to approve";
            break;
        }
        default:
            //ZEMU_LOGF(50, "View error show\n")
            view_error_show();
            break;
    }

    return true;
}

static void review_transaction() {
    const zxerr_t err = navigate_pages(0, LAST_PAGE_FOR_REVIEW, &total_pages);
    if (err != zxerr_ok) {
        view_error_show();
        return;
    }
    nbgl_useCaseRegularReview(0, total_pages + 1, REJECT_LABEL, NULL, transaction_screen_callback, confirm_transaction_callback);
}


static void review_transaction_shortcut() {
    const zxerr_t err = navigate_pages(0, LAST_PAGE_FOR_REVIEW, &total_pages);
    if (err != zxerr_ok) {
        view_error_show();
        return;
    }
    nbgl_useCaseForwardOnlyReview(REJECT_LABEL, NULL, transaction_screen_callback, confirm_transaction_callback);
}

static void review_configuration() {
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];
    const zxerr_t err = h_review_update_data();
    if (err != zxerr_ok)
    {
        //ZEMU_LOGF(50, "Config screen error\n")
        view_idle_show(0, NULL);
    }

    nbgl_useCaseChoice(&C_Eye_48px, BACKEND_LAZY.key, BACKEND_LAZY.message, "Accept", "Reject", confirm_setting);
}

static void review_address() {
    nbgl_layoutTagValueList_t* extraPagesPtr = NULL;

    if (app_mode_expert()) {
        pairs[0].item = BACKEND_LAZY.keys[1];
        pairs[0].value = BACKEND_LAZY.messages[1];

        BACKEND_LAZY.itemIdx = 1;
        BACKEND_LAZY.key = BACKEND_LAZY.keys[1];
        BACKEND_LAZY.message = BACKEND_LAZY.messages[1];
        h_review_update_data();

        pairList.nbMaxLinesForValue = 0;
        pairList.nbPairs = 1;
        pairList.pairs = pairs;

        extraPagesPtr = &pairList;
    }

    BACKEND_LAZY.itemIdx = 0;
    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];
    h_review_update_data();

    nbgl_useCaseAddressConfirmationExt(BACKEND_LAZY.message, confirm_transaction_callback, extraPagesPtr);
}

void view_review_show_impl(unsigned int requireReply){
    review_type = (review_type_e) requireReply;
    h_paging_init();

    BACKEND_LAZY.key = BACKEND_LAZY.keys[0];
    BACKEND_LAZY.message = BACKEND_LAZY.messages[0];
    zxerr_t err = h_review_update_data();
    if (err != zxerr_ok) {
        //ZEMU_LOGF(50, "Error updating data\n")
        return;
    }

    switch (review_type)
    {
        case REVIEW_UI:
            nbgl_useCaseReviewStart(&C_Eye_48px,
                                    "Review configuration",
                                    NULL,
                                    REJECT_LABEL,
                                    review_configuration,
                                    h_reject_internal);
            break;
        case REVIEW_ADDRESS:
            nbgl_useCaseReviewStart(&C_Eye_48px,
                                    "Review address",
                                    NULL,
                                    REJECT_LABEL,
                                    review_address,
                                    h_reject_internal);
            break;

        case REVIEW_TXN:
        default:
            nbgl_useCaseReviewStart(&C_Eye_48px,
                                    "Review transaction",
                                    NULL,
                                    REJECT_LABEL,
                                    app_mode_shortcut() ? review_transaction_shortcut : review_transaction,
                                    h_reject_internal);
    }
}

#endif
