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
// TODO: Remove later!!!!!
#include "tx.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];
uint32_t hdPath_len;

static cx_blake2b_t *ctx_blake2b = NULL;

#define CHECK_PARSER_OK(CALL)      \
  do {                         \
    cx_err_t __cx_err = CALL;  \
    if (__cx_err != parser_ok) {   \
      return zxerr_unknown;    \
    }                          \
  } while (0)

__Z_INLINE zxerr_t keccak_hash(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    // return actual size using value from signatureLength
    cx_sha3_t keccak;
    if (cx_keccak_init_no_throw(&keccak, outLen * 8) != CX_OK) return zxerr_unknown;
    CHECK_CX_OK(cx_hash_no_throw((cx_hash_t *)&keccak, CX_LAST, in, inLen, out, outLen));

    return zxerr_ok;
}

zxerr_t keccak_digest(const unsigned char *in, unsigned int inLen,
                          unsigned char *out, unsigned int outLen) {
    return keccak_hash(in, inLen, out, outLen);
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


typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;
} __attribute__((packed)) signature_t;

// DER signature max size should be 73
// https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
uint8_t der_signature[73];

zxerr_t _sign(uint8_t *output, uint16_t outputLen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize, unsigned int *info) {
    if (output == NULL || message == NULL || sigSize == NULL ||
        outputLen < sizeof(signature_t) || messageLen != CX_SHA256_SIZE) {
            return zxerr_invalid_crypto_settings;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SECP256K1_SK_LEN] = {0};
    size_t signatureLength = sizeof(der_signature);
    uint32_t tmpInfo = 0;
    *sigSize = 0;

    signature_t *const signature = (signature_t *) output;
    zxerr_t error = zxerr_unknown;

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL,
                                                     CX_CURVE_256K1,
                                                     hdPath,
                                                     hdPath_len, // HDPATH_LEN_DEFAULT?
                                                     privateKeyData,
                                                     NULL,
                                                     NULL,
                                                     0));

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                         CX_RND_RFC6979 | CX_LAST,
                                         CX_SHA256,
                                         message,
                                         messageLen,
                                         der_signature,
                                         &signatureLength, &tmpInfo));

    const err_convert_e err_c = convertDERtoRSV(der_signature, tmpInfo,  signature->r, signature->s, &signature->v);
    if (err_c == no_error) {
        *sigSize =  sizeof_field(signature_t, r) +
                    sizeof_field(signature_t, s) +
                    sizeof_field(signature_t, v) +
                    signatureLength;
        if (info != NULL) *info = tmpInfo;
        error = zxerr_ok;
    }

catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, sizeof(privateKeyData));

    if (error != zxerr_ok) {
        MEMZERO(output, outputLen);
    }

    return error;
}


zxerr_t crypto_sign_avax(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, const uint32_t *path, uint16_t path_len) {
    if (signatureMaxlen < sizeof(signature_t)) {
        return zxerr_buffer_too_small;
    }

    if (messageLen != CX_SHA256_SIZE) {
        return zxerr_out_of_bounds;
    }

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    int signatureLength = 0;
    unsigned int info = 0;

    signature_t *const signature = (signature_t *) buffer;

    zxerr_t zxerr = zxerr_unknown;
    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_len,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message,
                                            CX_SHA256_SIZE,
                                            der_signature,
                                            sizeof(der_signature),
                                            &info);

            zxerr = zxerr_ok;
        }
        CATCH_ALL {
            signatureLength = 0;
            zxerr = zxerr_ledger_api_error;
        };
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    if(zxerr != zxerr_ok) {
        return zxerr;
    }

    err_convert_e err = convertDERtoRSV(der_signature, info,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        return zxerr_encoding_failed;
    }

    return zxerr;
}

// Sign an ethereum related transaction
zxerr_t crypto_sign_eth(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK_256_SIZE] = {'\n'};
    CHECK_ZXERR(keccak_digest(message, messageLen, message_digest, KECCAK_256_SIZE))
    char data[KECCAK_256_SIZE * 2 + 1] = {0}; // Each byte needs 2 characters, plus null terminator


    unsigned int info = 0;
    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK_256_SIZE, sigSize, &info);
    if (error != zxerr_ok)
        return zxerr_invalid_crypto_settings;

    // we need to fix V
    uint8_t v = tx_compute_eth_v(info);

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return error;
}

// Sign an ethereum personal message
zxerr_t crypto_sign_eth_msg(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen, uint16_t *sigSize) {
    if (buffer == NULL || message == NULL || sigSize == NULL || signatureMaxlen < sizeof(signature_t)) {
        return zxerr_invalid_crypto_settings;
    }

    uint8_t message_digest[KECCAK_256_SIZE] = {'\n'};
    CHECK_ZXERR(keccak_digest(message, messageLen, message_digest, KECCAK_256_SIZE))

    char data[KECCAK_256_SIZE * 2 + 1] = {0}; // Each byte needs 2 characters, plus null terminator

    unsigned int info = 0;
    zxerr_t error = _sign(buffer, signatureMaxlen, message_digest, KECCAK_256_SIZE, sigSize, &info);
    if (error != zxerr_ok)
        return zxerr_invalid_crypto_settings;

    // we need to fix V
    uint8_t v = 27;

    if (info & CX_ECCINFO_PARITY_ODD)
        v += 1;

    if (info & CX_ECCINFO_xGTn)
        v += 2;

    // need to reorder signature as hw-eth-app expects v at the beginning.
    // so rsv -> vrs
    uint8_t rs_size = sizeof_field(signature_t, r) + sizeof_field(signature_t, s);
    memmove(buffer + 1, buffer, rs_size);
    buffer[0] = v;

    return error;
}



zxerr_t crypto_fillAddress(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen) {
    if (buffer == NULL || addrResponseLen == NULL) {
        return zxerr_unknown;
    }

    // MEMZERO(buffer, bufferLen);
    *addrResponseLen = 3 * KEY_LENGTH;

    return zxerr_ok;
}
