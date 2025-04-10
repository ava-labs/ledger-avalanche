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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <sigutils.h>
#include <stdbool.h>

#include "coin.h"
#include "zxerror.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];
extern uint32_t hdPath_len;

zxerr_t crypto_sign_avax(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, const uint32_t *path, uint16_t path_len, uint8_t curve_type);
zxerr_t crypto_fill_ed25519_address(uint8_t *buffer, uint16_t buffer_len, uint16_t *addrLen);

#ifdef __cplusplus
}
#endif
