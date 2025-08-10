#include "kdf.h"
#include "hash.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/* 
 * Maximum output length for HKDF-SHA256
 * Limited to 255 * hash length (32 bytes) = 8160 bytes
 */
#define HKDF_MAX_OUTPUT_LEN 8160

/**
 * @brief Internal function to perform HMAC-SHA256
 *
 * Computes HMAC-SHA256 of the input data using the provided key.
 *
 * @param key HMAC key
 * @param key_len Length of the key in bytes
 * @param data Input data to be hashed
 * @param data_len Length of the input data in bytes
 * @param output Buffer to store the HMAC result (32 bytes)
 *
 * @return 0 on success, negative value on error
 */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t output[32]) {
    crypto_auth_hmacsha256_state state;
    
    /* Validate parameters */
    if (!key || !data || !output) {
        return -1;
    }
    
    /* Use libsodium's HMAC-SHA256 implementation */
    if (crypto_auth_hmacsha256_init(&state, key, key_len) != 0) {
        return -2;
    }
    
    if (crypto_auth_hmacsha256_update(&state, data, data_len) != 0) {
        return -2;
    }
    
    if (crypto_auth_hmacsha256_final(&state, output) != 0) {
        return -2;
    }
    
    return 0;
}

int bn_hkdf_extract(const uint8_t *salt, size_t salt_len,
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t prk[32]) {
    uint8_t default_salt[32] = {0};
    const uint8_t *real_salt;
    size_t real_salt_len;
    
    /* Validate parameters */
    if (!ikm || !prk) {
        return -1;
    }
    
    /* If salt is NULL or empty, use a string of zeros */
    if (!salt || salt_len == 0) {
        real_salt = default_salt;
        real_salt_len = sizeof(default_salt);
    } else {
        real_salt = salt;
        real_salt_len = salt_len;
    }
    
    /* HKDF-Extract: PRK = HMAC-SHA256(salt, IKM) */
    int result = hmac_sha256(real_salt, real_salt_len, ikm, ikm_len, prk);
    if (result < 0) {
        return -2;
    }
    
    return 0;
}

int bn_hkdf_expand(const uint8_t prk[32],
                  const uint8_t *info, size_t info_len,
                  uint8_t *okm, size_t okm_len) {
    uint8_t t[32];               /* T(i) buffer */
    uint8_t t_and_info[2048];    /* Buffer for concatenated T(i-1) || info || i */
    size_t t_and_info_len;
    uint8_t counter = 1;
    size_t n, offset = 0;
    int result;
    
    /* Validate parameters */
    if (!prk || !okm) {
        return -1;
    }
    
    /* Check that the requested length doesn't exceed maximum allowed */
    if (okm_len > HKDF_MAX_OUTPUT_LEN) {
        return -2;
    }
    
    /* Handle empty info */
    if (!info) {
        info = (const uint8_t *)"";
        info_len = 0;
    }
    
    /* Check if the info length is too large for our buffer */
    if (info_len > sizeof(t_and_info) - 33) { /* 32 bytes for T(i-1) + 1 byte for counter */
        return -1;
    }
    
    /* Calculate number of iterations (ceiling of okm_len/32) */
    n = (okm_len + 31) / 32;
    
    /* First iteration (T(0) is empty) */
    t_and_info_len = 0;
    
    /* T(1) = HMAC-SHA256(PRK, info || 0x01) */
    memcpy(t_and_info + t_and_info_len, info, info_len);
    t_and_info_len += info_len;
    t_and_info[t_and_info_len++] = counter++;
    
    result = hmac_sha256(prk, 32, t_and_info, t_and_info_len, t);
    if (result < 0) {
        return -3;
    }
    
    /* Copy the first block of output */
    if (okm_len < 32) {
        memcpy(okm, t, okm_len);
        return 0;
    }
    memcpy(okm, t, 32);
    offset = 32;
    
    /* Subsequent iterations */
    for (size_t i = 1; i < n; i++) {
        /* T(i+1) = HMAC-SHA256(PRK, T(i) || info || i+1) */
        memcpy(t_and_info, t, 32);
        memcpy(t_and_info + 32, info, info_len);
        t_and_info_len = 32 + info_len;
        t_and_info[t_and_info_len++] = counter++;
        
        result = hmac_sha256(prk, 32, t_and_info, t_and_info_len, t);
        if (result < 0) {
            /* Securely wipe any sensitive data */
            sodium_memzero(t, sizeof(t));
            sodium_memzero(t_and_info, sizeof(t_and_info));
            return -3;
        }
        
        /* Copy to output */
        if (offset + 32 <= okm_len) {
            memcpy(okm + offset, t, 32);
            offset += 32;
        } else {
            /* Last partial block */
            memcpy(okm + offset, t, okm_len - offset);
            break;
        }
    }
    
    /* Securely wipe any sensitive data */
    sodium_memzero(t, sizeof(t));
    sodium_memzero(t_and_info, sizeof(t_and_info));
    
    return 0;
}

int bn_hkdf(const uint8_t *salt, size_t salt_len,
           const uint8_t *ikm, size_t ikm_len,
           const uint8_t *info, size_t info_len,
           uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    int result;
    
    /* Validate parameters */
    if (!ikm || !okm) {
        return -1;
    }
    
    /* Check that the requested length doesn't exceed maximum allowed */
    if (okm_len > HKDF_MAX_OUTPUT_LEN) {
        return -2;
    }
    
    /* Extract phase */
    result = bn_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (result < 0) {
        return -3;
    }
    
    /* Expand phase */
    result = bn_hkdf_expand(prk, info, info_len, okm, okm_len);
    
    /* Securely wipe the PRK */
    sodium_memzero(prk, sizeof(prk));
    
    if (result < 0) {
        return -3;
    }
    
    return 0;
}

int bn_hkdf_expand_label(const uint8_t prk[32],
                        const char *label, const uint8_t *context, size_t context_len,
                        uint8_t *out, size_t out_len) {
    /* 
     * TLS 1.3 style label formatting:
     * struct {
     *     uint16 length;               // desired output length (big-endian)
     *     opaque label<7..255>;        // protocol label
     *     opaque context<0..255>;      // optional context
     * } HkdfLabel;
     */
    uint8_t hkdf_label[512];
    size_t hkdf_label_len = 0;
    size_t label_len;
    
    /* Validate parameters */
    if (!prk || !label || !out) {
        return -1;
    }
    
    if (out_len > HKDF_MAX_OUTPUT_LEN || out_len > 0xFFFF) {
        return -2;
    }
    
    /* Compute actual lengths */
    label_len = strlen(label);
    if (label_len > 255 || label_len < 7) {
        return -1;
    }
    
    if (!context) {
        context_len = 0;
    }
    
    if (context_len > 255) {
        return -1;
    }
    
    /* Ensure the buffer is large enough */
    if (2 + 1 + label_len + 1 + context_len > sizeof(hkdf_label)) {
        return -1;
    }
    
    /* Construct the HKDF label according to TLS 1.3 format */
    
    /* Length (2 bytes, big-endian) */
    hkdf_label[hkdf_label_len++] = (uint8_t)(out_len >> 8);
    hkdf_label[hkdf_label_len++] = (uint8_t)(out_len & 0xFF);
    
    /* Label length and value */
    hkdf_label[hkdf_label_len++] = (uint8_t)label_len;
    memcpy(hkdf_label + hkdf_label_len, label, label_len);
    hkdf_label_len += label_len;
    
    /* Context length and value */
    hkdf_label[hkdf_label_len++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(hkdf_label + hkdf_label_len, context, context_len);
        hkdf_label_len += context_len;
    }
    
    /* Call HKDF-Expand with the formatted label as info */
    int result = bn_hkdf_expand(prk, hkdf_label, hkdf_label_len, out, out_len);
    
    /* Securely wipe the label buffer */
    sodium_memzero(hkdf_label, sizeof(hkdf_label));
    
    return result;
}