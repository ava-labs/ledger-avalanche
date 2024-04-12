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

#include "crypto.h"

#include "coin.h"
#include "cx.h"
#include "zxmacros.h"
#include "keys_def.h"
#include "crypto_helper.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

#define CHECK_PARSER_OK(CALL)      \
  do {                         \
    cx_err_t __cx_err = CALL;  \
    if (__cx_err != parser_ok) {   \
      return zxerr_unknown;    \
    }                          \
  } while (0)

static zxerr_t computeKeys(keys_t * saplingKeys) {
    if (saplingKeys == NULL) {
        return zxerr_no_data;
    }

    // Compute ask, nsk
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_ASK, saplingKeys->ask, true));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_NSK, saplingKeys->nsk, true));

    // Compute ak, nsk
    // This function will make a copy of the first param --> There shouldn't be problems to overwrite the union
    CHECK_PARSER_OK(generate_key(saplingKeys->ask, SpendingKeyGenerator, saplingKeys->ak));
    CHECK_PARSER_OK(generate_key(saplingKeys->nsk, ProofGenerationKeyGenerator, saplingKeys->nk));

    // Compute ivk and ovk
    CHECK_PARSER_OK(computeIVK(saplingKeys->ak, saplingKeys->nk, saplingKeys->ivk));
    CHECK_PARSER_OK(convertKey(saplingKeys->spendingKey, MODIFIER_OVK, saplingKeys->ovk, false));

    // Compute public address
    CHECK_PARSER_OK(generate_key(saplingKeys->ivk, PublicKeyGenerator, saplingKeys->address));

    return zxerr_ok;
}

zxerr_t crypto_generateSaplingKeys(uint8_t *output, uint16_t outputLen) {
    if (output == NULL || outputLen < 3 * KEY_LENGTH) {
        return zxerr_buffer_too_small;
    }

    zxerr_t error = zxerr_unknown;
    MEMZERO(output, outputLen);

    // Generate spending key
    uint8_t privateKeyData[SK_LEN_25519] = {0};
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_Ed25519,
                                                     hdPath,
                                                     HDPATH_LEN_DEFAULT,
                                                     privateKeyData,
                                                     NULL, NULL, 0));

    keys_t saplingKeys = {0};
    memcpy(saplingKeys.spendingKey, privateKeyData, KEY_LENGTH);
    error = computeKeys(&saplingKeys);

    // Copy keys
    if (error == zxerr_ok) {
        memcpy(output, saplingKeys.address, KEY_LENGTH);
        memcpy(output + KEY_LENGTH, saplingKeys.ivk, KEY_LENGTH);
        memcpy(output + 2*KEY_LENGTH, saplingKeys.ovk, KEY_LENGTH);
    }

catch_cx_error:
    MEMZERO(privateKeyData, sizeof(privateKeyData));
    MEMZERO(&saplingKeys, sizeof(saplingKeys));

    return error;
}


zxerr_t crypto_extractPublicKey(uint8_t *pubKey, uint16_t pubKeyLen) {
    if (pubKey == NULL || pubKeyLen < PK_LEN_25519) {
        return zxerr_invalid_crypto_settings;
    }
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    zxerr_t error = zxerr_unknown;

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519, hdPath, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1));
    for (unsigned int i = 0; i < PK_LEN_25519; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }

    if ((cx_publicKey.W[PK_LEN_25519] & 1) != 0) {
        pubKey[31] |= 0x80;
    }
    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(pubKey, pubKeyLen);
    }
    return error;
}

zxerr_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen) {
    if (signature == NULL || message == NULL || signatureMaxlen < ED25519_SIGNATURE_SIZE || messageLen == 0) {
        return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    zxerr_t error = zxerr_unknown;
    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519, hdPath, HDPATH_LEN_DEFAULT,
                                                     privateKeyData, NULL, NULL, 0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SCALAR_LEN_ED25519, &cx_privateKey));

    // Sign
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey, CX_SHA512, message, messageLen, signature, signatureMaxlen));

    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(signature, signatureMaxlen);
    }

    return error;
}

zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen) {
    if (buffer == NULL || addrResponseLen == NULL) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    // CHECK_ZXERR(crypto_generateSaplingKeys(buffer, bufferLen));
    *addrResponseLen = 3 * KEY_LENGTH;

    return zxerr_ok;
}
