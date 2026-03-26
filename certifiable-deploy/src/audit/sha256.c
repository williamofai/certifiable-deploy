/**
 * @file sha256.c
 * @brief FIPS 180-4 compliant SHA-256 implementation
 * @traceability CD-MATH-001 §1, SRS-002-ATTEST
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_audit.h"
#include <string.h>

/*============================================================================
 * SHA-256 Constants
 *============================================================================*/

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*============================================================================
 * Bit Operations
 *============================================================================*/

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/*============================================================================
 * Internal State
 *============================================================================*/

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_state_t;

/*============================================================================
 * Transform
 *============================================================================*/

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* Update state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/*============================================================================
 * Public API
 *============================================================================*/

void cd_sha256_init(cd_sha256_ctx_t *ctx) {
    sha256_state_t *s = (sha256_state_t *)ctx->state;
    memcpy(s->state, H_INIT, sizeof(H_INIT));
    s->count = 0;
    memset(s->buffer, 0, sizeof(s->buffer));
    ctx->finalized = false;
}

void cd_sha256_update(cd_sha256_ctx_t *ctx, const void *data, size_t len) {
    sha256_state_t *s = (sha256_state_t *)ctx->state;
    const uint8_t *p = (const uint8_t *)data;
    size_t buf_idx, fill;

    if (ctx->finalized || len == 0) return;

    buf_idx = (size_t)(s->count & 63);
    s->count += len;

    if (buf_idx > 0) {
        fill = 64 - buf_idx;
        if (len < fill) {
            memcpy(s->buffer + buf_idx, p, len);
            return;
        }
        memcpy(s->buffer + buf_idx, p, fill);
        sha256_transform(s->state, s->buffer);
        p += fill;
        len -= fill;
    }

    while (len >= 64) {
        sha256_transform(s->state, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(s->buffer, p, len);
    }
}

void cd_sha256_final(cd_sha256_ctx_t *ctx, cd_hash_t *out) {
    sha256_state_t *s = (sha256_state_t *)ctx->state;
    uint64_t bit_count;
    size_t buf_idx, pad_len;
    uint8_t pad[72];
    int i;

    if (ctx->finalized) {
        memset(out->bytes, 0, CD_HASH_SIZE);
        return;
    }

    bit_count = s->count * 8;
    buf_idx = (size_t)(s->count & 63);
    pad_len = (buf_idx < 56) ? (56 - buf_idx) : (120 - buf_idx);

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /* Append bit count in big-endian */
    pad[pad_len + 0] = (uint8_t)(bit_count >> 56);
    pad[pad_len + 1] = (uint8_t)(bit_count >> 48);
    pad[pad_len + 2] = (uint8_t)(bit_count >> 40);
    pad[pad_len + 3] = (uint8_t)(bit_count >> 32);
    pad[pad_len + 4] = (uint8_t)(bit_count >> 24);
    pad[pad_len + 5] = (uint8_t)(bit_count >> 16);
    pad[pad_len + 6] = (uint8_t)(bit_count >> 8);
    pad[pad_len + 7] = (uint8_t)(bit_count);

    cd_sha256_update(ctx, pad, pad_len + 8);

    /* Output in big-endian */
    for (i = 0; i < 8; i++) {
        out->bytes[i * 4 + 0] = (uint8_t)(s->state[i] >> 24);
        out->bytes[i * 4 + 1] = (uint8_t)(s->state[i] >> 16);
        out->bytes[i * 4 + 2] = (uint8_t)(s->state[i] >> 8);
        out->bytes[i * 4 + 3] = (uint8_t)(s->state[i]);
    }

    ctx->finalized = true;
}

void cd_sha256(const void *data, size_t len, cd_hash_t *out) {
    cd_sha256_ctx_t ctx;
    cd_sha256_init(&ctx);
    cd_sha256_update(&ctx, data, len);
    cd_sha256_final(&ctx, out);
}
