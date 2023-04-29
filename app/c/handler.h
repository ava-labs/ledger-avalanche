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

#include "boilerplate/io.h"
#include "boilerplate/sw.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

#include <os_io_seproxyhal.h>
#include <os.h>

#define APDU_INDEX_CLA 0
#define OFFSET_CLA 0

void app_exit();
void btc_state_reset();

unsigned char handle_event(unsigned char channel);
void handle_btc_apdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx,  const uint8_t *buffer, uint16_t bufferLen);
void initialize_app_globals();

