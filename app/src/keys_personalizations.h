/*******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

#include <stddef.h>
#include <stdint.h>

#if defined (LEDGER_SPECIFIC)
// blake2 needs to define output size in bits 512 bits = 64 bytes
#define BLAKE2B_OUTPUT_LEN 512
#else
#define BLAKE2B_OUTPUT_LEN 64
#endif

const char EXPANDED_SPEND_BLAKE2_KEY[16] = "Iron Fish Money ";
const char CRH_IVK_PERSONALIZATION[8] = "Zcashivk";

#ifdef __cplusplus
}
#endif


