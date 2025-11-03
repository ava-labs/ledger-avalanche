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

#define CLA 0x80

#define MAX_BIP32_PATH 10
#define HDPATH_LEN_DEFAULT 5
#define HDPATH_0_DEFAULT (0x80000000u | 0x2c)  // 44
#define HDPATH_1_DEFAULT (0x80000000u | 0x85)  // 133

#define HDPATH_2_DEFAULT (0x80000000u | 0u)
#define HDPATH_3_DEFAULT (0u)
#define HDPATH_4_DEFAULT (0u)

#define HDPATH_ETH_0_DEFAULT (0x80000000u | 0x2cu)
#define HDPATH_ETH_1_DEFAULT (0x80000000u | 0x3cu)

#define SECP256K1_PK_LEN 65u
#define SECP256K1_SK_LEN 64u

#define SK_LEN_25519 64u
#define SCALAR_LEN_ED25519 32u
#define SIG_PLUS_TYPE_LEN 65u

#define ED25519_SIGNATURE_SIZE 64u

#define PK_LEN_25519 32u

#define COIN_AMOUNT_DECIMAL_PLACES 6
#define COIN_TICKER "AVAX "

#define MENU_MAIN_APP_LINE1 "Avalanche"
#define MENU_MAIN_APP_LINE2 "Ready"

#define MENU_MAIN_APP_LINE2_SECRET "???"
#define APPVERSION_LINE1 "Avalanche"
#define APPVERSION_LINE2 "v" APPVERSION

#define AVX_CLA 0x80
#define ETH_CLA 0xE0

// AVAX instructions:
#define AVX_INS_GET_VERSION 0x00
#define AVX_INS_GET_WALLET_ID 0x01
#define AVX_GET_PUBLIC_KEY 0x02
#define AVX_INS_GET_EXTENDED_PUBLIC_KEY 0x03
#define AVX_SIGN_HASH 0x04
#define AVX_SIGN 5
#define AVX_SIGN_MSG 0x06

// ETH instructions:
#define INS_ETH_GET_PUBLIC_KEY 0x02
#define INS_ETH_SIGN 4
#define INS_ETH_GET_APP_CONFIGURATION 0x06
#define INS_SET_PLUGIN 0x16
#define INS_PROVIDE_NFT_INFORMATION 0x14
#define INS_ETH_PROVIDE_ERC20 0x0A
#define INS_SIGN_ETH_MSG 0x08
// Definitions use to handle hash signing
// if P1 == FIRST_MESSAGE, it means we have in front of a normal
// hash signing where the received path is the root path and a hash
// that must be shown to the user.
// otherwise we use a previously stored rooth hash, and the received
// path prefix to compute the new path and sign the hash which was also
// previously stored and sign it.
#define FIRST_MESSAGE 0x01
#define NEXT_MESSAGE 0x03
#define LAST_MESSAGE 0x02

// transaction is sent as a blob of rlp encoded bytes,
#define P1_ETH_FIRST 0x00
#define P1_ETH_MORE 0x80
// eth address chain_code allowed valuec
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01

#define CURVE_SECP256K1 0x00
#define CURVE_ED25519 0x01
#define PK_LEN_ED25519 32
#define ED25519_AUTH_ID 0x00
#define HASH_LEN 32
#define ADDRESS_BUFFER_LEN 33  // 1 byte auth_id + 32 bytes hash
#define ADDRESS_CHECKSUM_LEN 4
#define ADDRESS_MAX_SIZE 50
#define HASH_OFFSET 28

#ifdef __cplusplus
}
#endif
