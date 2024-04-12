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

// #{TODO} ---> Replace CLA, Token symbol, HDPATH, etc etc
#define CLA 0x80

#define HDPATH_LEN_DEFAULT 5
#define HDPATH_0_DEFAULT (0x80000000u | 0x2c)   // 44
#define HDPATH_1_DEFAULT (0x80000000u | 0x85)  // 133

#define HDPATH_2_DEFAULT (0x80000000u | 0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define SECP256K1_PK_LEN 65u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define ED25519_SIGNATURE_SIZE 64u

#define PK_LEN_25519 32u

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "IRON "

#define MENU_MAIN_APP_LINE1 "Ironfish"
#define MENU_MAIN_APP_LINE2 "Ready"
#define MENU_MAIN_APP_LINE2_SECRET "???"
#define APPVERSION_LINE1 "Ironfish"
#define APPVERSION_LINE2 "v" APPVERSION

// AVAX instructions:
#define AVX_CLA 0x80

#define AVX_INS_GET_VERSION 0x00
#define AVX_INS_GET_WALLET_ID 0x01
#define AVX_INS_GET_PUBLIC_KEY 0x02
#define AVX_INS_GET_EXTENDED_PUBLIC_KEY 0x03
#define AVX_INS_SIGN_HASH 0x04
#define AVX_INS_SIGN 0x05
#define AVX_INS_SIGN_MSG 0x06

#ifdef __cplusplus
}
#endif
