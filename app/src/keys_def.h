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
typedef struct {
    uint8_t *ptr;
    uint16_t len;
} bytes_t;

typedef enum {
    SpendingKeyGenerator,
    ProofGenerationKeyGenerator,
    PublicKeyGenerator,
    InvalidKey,
} constant_key_t;

#define KEY_LENGTH 32

typedef uint8_t spending_key_t[KEY_LENGTH];
typedef uint8_t ask_t[KEY_LENGTH];
typedef uint8_t nsk_t[KEY_LENGTH];

typedef uint8_t ak_t[KEY_LENGTH];
typedef uint8_t nk_t[KEY_LENGTH];

typedef uint8_t ivk_t[KEY_LENGTH];
typedef uint8_t ovk_t[KEY_LENGTH];

typedef uint8_t public_address_t[KEY_LENGTH];

typedef struct {
    spending_key_t spendingKey;
    union {
        ask_t ask;
        ak_t ak;
    };
    union {
        nsk_t nsk;
        nk_t nk;
    };

    ivk_t ivk;
    ovk_t ovk;
    public_address_t address;
} keys_t;

#ifdef __cplusplus
}
#endif
