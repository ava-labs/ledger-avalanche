/*******************************************************************************
 *   (c) 2016 Ledger
 *   (c) 2018-2024 Zondax AG
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

#define CLA_ETH 0xE0
// commands bellow from eip712
// APDUs P1
#define P1_COMPLETE 0x00
#define P1_PARTIAL  0xFF

// APDUs P2
#define P2_DEF_NAME          0x00
#define P2_DEF_FIELD         0xFF
#define P2_IMPL_NAME         P2_DEF_NAME
#define P2_IMPL_ARRAY        0x0F
#define P2_IMPL_FIELD        P2_DEF_FIELD
#define P2_FILT_ACTIVATE     0x00
#define P2_FILT_MESSAGE_INFO 0x0F
#define P2_FILT_SHOW_FIELD   0xFF

#define DOMAIN_STRUCT_NAME "EIP712Domain"

// Commands bellow from Ethereum app
#define INS_GET_PUBLIC_KEY                  0x02
#define INS_SIGN                            0x04
#define INS_GET_APP_CONFIGURATION           0x06
#define INS_SIGN_PERSONAL_MESSAGE           0x08
#define INS_PROVIDE_ERC20_TOKEN_INFORMATION 0x0A
#define INS_SIGN_EIP_712_MESSAGE            0x0C
#define INS_GET_ETH2_PUBLIC_KEY             0x0E
#define INS_SET_ETH2_WITHDRAWAL_INDEX       0x10
#define INS_SET_EXTERNAL_PLUGIN             0x12
#define INS_PROVIDE_NFT_INFORMATION         0x14
#define INS_SET_PLUGIN                      0x16
#define INS_PERFORM_PRIVACY_OPERATION       0x18
#define INS_EIP712_STRUCT_DEF               0x1A
#define INS_EIP712_STRUCT_IMPL              0x1C
#define INS_EIP712_FILTERING                0x1E
#define INS_ENS_GET_CHALLENGE               0x20
#define INS_ENS_PROVIDE_INFO                0x22
#define P1_CONFIRM                          0x01
#define P1_NON_CONFIRM                      0x00
#define P2_NO_CHAINCODE                     0x00
#define P2_CHAINCODE                        0x01
#define P1_FIRST                            0x00
#define P1_MORE                             0x80
#define P2_EIP712_LEGACY_IMPLEM             0x00
#define P2_EIP712_FULL_IMPLEM               0x01

#define COMMON_CLA 0xB0

#define APDU_RESPONSE_OK                      0x9000
#define APDU_RESPONSE_ERROR_NO_INFO           0x6a00
#define APDU_RESPONSE_INVALID_DATA            0x6a80
#define APDU_RESPONSE_INSUFFICIENT_MEMORY     0x6a84
#define APDU_RESPONSE_INVALID_INS             0x6d00
#define APDU_RESPONSE_INVALID_P1_P2           0x6b00
#define APDU_RESPONSE_CONDITION_NOT_SATISFIED 0x6985
#define APDU_RESPONSE_REF_DATA_NOT_FOUND      0x6a88
#define APDU_RESPONSE_UNKNOWN                 0x6f00

// enum { OFFSET_CLA = 0, OFFSET_INS, OFFSET_P1, OFFSET_P2, OFFSET_LC, OFFSET_CDATA };

#define ERR_APDU_EMPTY         0x6982
#define ERR_APDU_SIZE_MISMATCH 0x6983
