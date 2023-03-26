/*******************************************************************************
 *   (c) 2019 Zondax GmbH
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
#pragma once

#include "coin.h"
#include "view.h"
#include "zxerror.h"
#include <stdbool.h>
#include <stdint.h>

#define CUR_FLOW G_ux.flow_stack[G_ux.stack_count - 1]

#define APPROVE_LABEL "APPROVE"
#define REJECT_LABEL "REJECT"

#if defined(TARGET_NANOS)

#define KEY_SIZE 17
#define MESSAGE_SIZE 17

typedef struct NanoSBackend {
  uint8_t key[KEY_SIZE + 1];
  uint8_t value[MESSAGE_SIZE + 1];
  uint8_t value2[MESSAGE_SIZE + 1];
  uintptr_t viewable_size;
  bool expert;
} NanoSBackend;

extern struct NanoSBackend BACKEND_LAZY;

#elif defined(TARGET_NANOX)

#define KEY_SIZE 63
#define MESSAGE_SIZE 4095

typedef struct NanoXBackend {
  uint8_t key[KEY_SIZE + 1];
  uint8_t message[MESSAGE_SIZE + 1];
  uintptr_t viewable_size;
  bool expert;
  bool flow_inside_loop;
} NanoXBackend;

extern struct NanoXBackend BACKEND_LAZY;

#elif defined(TARGET_NANOS2)

#define KEY_SIZE 63
#define MESSAGE_SIZE 4095

typedef struct NanoSPBackend {
  uint8_t key[KEY_SIZE + 1];
  uint8_t message[MESSAGE_SIZE + 1];
  uintptr_t viewable_size;
  bool expert;
  bool flow_inside_loop;
} NanoSPBackend;

extern struct NanoSPBackend BACKEND_LAZY;

#elif defined(TARGET_STAX)

#define KEY_SIZE 64
#define MESSAGE_SIZE 4096

#define MAX_ITEMS 4
#define MAX_LINES_PER_FIELD 8
/* #define MAX_CHARS_PER_KEY_LINE      64 */
/* #define MAX_CHARS_PER_VALUE1_LINE   180 */
/* #define MAX_CHARS_HEXMESSAGE        160 */

typedef struct UIItem {
  char *title[KEY_SIZE];
  char *message[MESSAGE_SIZE];
} UIItem;

typedef struct StaxBackend {
  struct UIItem items[MAX_ITEMS];
  uintptr_t items_len;

  uintptr_t viewable_size;

  void *nbgl_page_content;
} StaxBackend;

extern struct StaxBackend BACKEND_LAZY;

#endif

#if defined(BLIND_SIGN_TOGGLE)
typedef struct blind_sign_toggle_t {
  bool toggle;
  char message[8 + 1];
} blind_sign_toggle_t;

extern blind_sign_toggle_t blind_sign;

void h_blind_sign_toggle();
void h_blind_sign_update();
#endif
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////

void view_idle_show_impl(uint8_t item_idx, char *statusString);
void view_init_impl(uint8_t *msg);
