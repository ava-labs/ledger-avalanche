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
#include "cx_blake2b.h"
#include "zxmacros.h"
#include "keys_def.h"
#include "crypto_helper.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint32_t hdPath_len;

#define CHECK_PARSER_OK(CALL)      \
  do {                         \
    cx_err_t __cx_err = CALL;  \
    if (__cx_err != parser_ok) {   \
      return zxerr_unknown;    \
    }                          \
  } while (0)

zxerr_t crypto_sign_avax_ed25519(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, const uint32_t *path, uint16_t path_len) {
    zemu_log_stack("crypto_sign_avax_ed25519");
    if (buffer == NULL || message == NULL ||
        signatureMaxlen < ED25519_SIGNATURE_SIZE || messageLen != CX_SHA256_SIZE) {
        return zxerr_unknown;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64] = {0};

    zxerr_t error = zxerr_unknown;
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_Ed25519,
                                                     path,
                                                     path_len,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey,
                                         CX_SHA512,
                                         message,
                                         messageLen,
                                         buffer,
                                         signatureMaxlen));

    error = zxerr_ok;

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(buffer, signatureMaxlen);
    }

    return error;
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;
} __attribute__((packed)) signature_t;

zxerr_t crypto_sign_avax_secp256k1(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, const uint32_t *path, uint16_t path_len) {
    if (signatureMaxlen < sizeof(signature_t)) {
        return zxerr_buffer_too_small;
    }

    if (messageLen != CX_SHA256_SIZE) {
        return zxerr_out_of_bounds;
    }

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73] = {0};

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64];
    size_t signatureLength = sizeof(der_signature);
    uint32_t info = 0;


    signature_t *const signature = (signature_t *) buffer;

    zxerr_t zxerr = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_256K1,
                                                     path,
                                                     path_len,
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));
    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                         CX_RND_RFC6979 | CX_LAST,
                                         CX_SHA256,
                                         message,
                                         CX_SHA256_SIZE,
                                         der_signature,
                                         &signatureLength, &info));

    const err_convert_e err_c = convertDERtoRSV(der_signature, info,  signature->r, signature->s, &signature->v);
    if (err_c == no_error) {
        zxerr = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));
    MEMZERO(der_signature, sizeof(der_signature));

    if (zxerr != zxerr_ok) {
        MEMZERO(buffer, signatureMaxlen);
    }

    return zxerr;
}

zxerr_t crypto_sign_avax(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, const uint32_t *path, uint16_t path_len, uint8_t curve_type) {

    zemu_log_stack("crypto_sign_avax");
    for (int i = 0; i < 32; i++) {
        ZEMU_LOGF(50,"%x", message[i]);
    }
    zemu_log_stack("crypto_sign_avax");
    switch (curve_type) {
        case SECP256K1_TYPE:
            return crypto_sign_avax_secp256k1(buffer, signatureMaxlen, message, messageLen, path, path_len);
        case ED25519_TYPE:
            return crypto_sign_avax_ed25519(buffer, signatureMaxlen, message, messageLen, path, path_len);
        default:
            return zxerr_unknown;
    }
    return zxerr_unknown;
}
