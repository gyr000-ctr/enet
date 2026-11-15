/**
 @file  crypto.c
 @brief Optional packet-level AEAD encryption for ENet.

 Self-contained implementation of ChaCha20-Poly1305 (RFC 8439), SHA-256,
 HMAC-SHA256 and HKDF (RFC 5869).  No external dependencies, no heap
 allocation on the per-packet path, no logging of key material.
*/
#include <string.h>
#include <stdlib.h>
#define ENET_BUILDING_LIB 1
#include "enet/utility.h"
#include "enet/time.h"
#include "enet/enet.h"

#ifdef _WIN32
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

/* ===================================================================== */
/* constant-time helpers                                                 */
/* ===================================================================== */

void
enet_crypto_memzero (void * data, size_t length)
{
    volatile enet_uint8 * p = (volatile enet_uint8 *) data;

    while (length --)
      * p ++ = 0;
}

int
enet_crypto_equal (const void * a, const void * b, size_t length)
{
    const enet_uint8 * x = (const enet_uint8 *) a,
                     * y = (const enet_uint8 *) b;
    enet_uint8 diff = 0;

    while (length --)
      diff |= (enet_uint8) (* x ++ ^ * y ++);

    return diff == 0;
}

/* ===================================================================== */
/* randomness                                                            */
/* ===================================================================== */

int
enet_crypto_random (enet_uint8 * out, size_t length)
{
#ifdef _WIN32
    HCRYPTPROV provider;

    if (CryptAcquireContext (& provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        BOOL ok = CryptGenRandom (provider, (DWORD) length, out);
        CryptReleaseContext (provider, 0);
        if (ok)
          return 0;
    }
#else
    static int urandomFd = -2;
    ssize_t got;
    size_t done = 0;

    if (urandomFd == -2)
      urandomFd = open ("/dev/urandom", O_RDONLY);

    if (urandomFd >= 0)
    {
        while (done < length)
        {
            got = read (urandomFd, out + done, length - done);
            if (got < 0)
            {
                if (errno == EINTR)
                  continue;
                break;
            }
            done += (size_t) got;
        }
        if (done == length)
          return 0;
    }
#endif

    /* Fallback for platforms without an OS RNG: hash together time, a
       monotonic counter and stack/heap addresses.  This is not
       cryptographically strong, but keeps the protocol functional. */
    {
        static enet_uint64 counter = 0;
        enet_uint8 material [64], digest [32];
        enet_uint32 t = enet_time_get ();
        size_t off = 0;

        memset (material, 0, sizeof (material));
        while (off < length)
        {
            memcpy (material, & t, sizeof (t));
            memcpy (material + sizeof (t), & counter, sizeof (counter));
            memcpy (material + sizeof (t) + sizeof (counter), & out, sizeof (out));
            memcpy (material + sizeof (t) + sizeof (counter) + sizeof (out), & material, sizeof (void *));
            enet_sha256 (material, sizeof (material), digest);

            {
                size_t chunk = length - off;
                if (chunk > sizeof (digest))
                  chunk = sizeof (digest);
                memcpy (out + off, digest, chunk);
                off += chunk;
            }
            ++ counter;
        }
        enet_crypto_memzero (material, sizeof (material));
        enet_crypto_memzero (digest, sizeof (digest));
    }

    return 0;
}

/* ===================================================================== */
/* SHA-256                                                               */
/* ===================================================================== */

typedef struct _ENetSHA256
{
   enet_uint32 state [8];
   enet_uint8  block [64];
   size_t      blockLength;
   enet_uint64 totalLength;
} ENetSHA256;

static const enet_uint32 sha256K [64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SHA256_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void
enet_sha256_transform (enet_uint32 state [8], const enet_uint8 block [64])
{
    enet_uint32 w [64], a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; ++ i)
      w [i] = ((enet_uint32) block [i * 4] << 24) |
              ((enet_uint32) block [i * 4 + 1] << 16) |
              ((enet_uint32) block [i * 4 + 2] << 8) |
              ((enet_uint32) block [i * 4 + 3]);

    for (i = 16; i < 64; ++ i)
    {
        enet_uint32 s0 = SHA256_ROTR (w [i - 15], 7) ^ SHA256_ROTR (w [i - 15], 18) ^ (w [i - 15] >> 3),
                    s1 = SHA256_ROTR (w [i - 2], 17) ^ SHA256_ROTR (w [i - 2], 19) ^ (w [i - 2] >> 10);
        w [i] = w [i - 16] + s0 + w [i - 7] + s1;
    }

    a = state [0]; b = state [1]; c = state [2]; d = state [3];
    e = state [4]; f = state [5]; g = state [6]; h = state [7];

    for (i = 0; i < 64; ++ i)
    {
        enet_uint32 s1 = SHA256_ROTR (e, 6) ^ SHA256_ROTR (e, 11) ^ SHA256_ROTR (e, 25),
                    ch = (e & f) ^ (~ e & g),
                    temp1 = h + s1 + ch + sha256K [i] + w [i],
                    s0 = SHA256_ROTR (a, 2) ^ SHA256_ROTR (a, 13) ^ SHA256_ROTR (a, 22),
                    maj = (a & b) ^ (a & c) ^ (b & c),
                    temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state [0] += a; state [1] += b; state [2] += c; state [3] += d;
    state [4] += e; state [5] += f; state [6] += g; state [7] += h;
}

static void
enet_sha256_init (ENetSHA256 * ctx)
{
    static const enet_uint32 initial [8] =
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    memcpy (ctx -> state, initial, sizeof (initial));
    ctx -> blockLength = 0;
    ctx -> totalLength = 0;
}

static void
enet_sha256_update (ENetSHA256 * ctx, const enet_uint8 * data, size_t length)
{
    ctx -> totalLength += length;

    while (length > 0)
    {
        size_t space = sizeof (ctx -> block) - ctx -> blockLength,
               chunk = length < space ? length : space;

        memcpy (ctx -> block + ctx -> blockLength, data, chunk);
        ctx -> blockLength += chunk;
        data += chunk;
        length -= chunk;

        if (ctx -> blockLength == sizeof (ctx -> block))
        {
            enet_sha256_transform (ctx -> state, ctx -> block);
            ctx -> blockLength = 0;
        }
    }
}

static void
enet_sha256_final (ENetSHA256 * ctx, enet_uint8 digest [32])
{
    enet_uint64 bitLength = ctx -> totalLength * 8;
    enet_uint8 lengthBlock [8];
    int i;

    for (i = 0; i < 8; ++ i)
      lengthBlock [i] = (enet_uint8) (bitLength >> (56 - i * 8));

    {
        enet_uint8 pad = 0x80;
        enet_sha256_update (ctx, & pad, 1);
    }
    while (ctx -> blockLength != 56)
    {
        enet_uint8 zero = 0;
        enet_sha256_update (ctx, & zero, 1);
    }
    /* totalLength bookkeeping is no longer needed; feed the length block
       directly through the update path (it only appends to the buffer). */
    {
        ENetSHA256 lengthOnly = * ctx;
        enet_sha256_update (& lengthOnly, lengthBlock, 8);
        for (i = 0; i < 8; ++ i)
        {
            digest [i * 4]     = (enet_uint8) (lengthOnly.state [i] >> 24);
            digest [i * 4 + 1] = (enet_uint8) (lengthOnly.state [i] >> 16);
            digest [i * 4 + 2] = (enet_uint8) (lengthOnly.state [i] >> 8);
            digest [i * 4 + 3] = (enet_uint8) (lengthOnly.state [i]);
        }
        enet_crypto_memzero (& lengthOnly, sizeof (lengthOnly));
    }
    enet_crypto_memzero (ctx, sizeof (* ctx));
}

void
enet_sha256 (const enet_uint8 * data, size_t length, enet_uint8 digest [32])
{
    ENetSHA256 ctx;

    enet_sha256_init (& ctx);
    enet_sha256_update (& ctx, data, length);
    enet_sha256_final (& ctx, digest);
}

/* ===================================================================== */
/* HMAC-SHA256 / HKDF                                                    */
/* ===================================================================== */

typedef struct _ENetHMAC
{
   ENetSHA256 inner;
   enet_uint8 outerPad [64];
} ENetHMAC;

static void
enet_hmac_init (ENetHMAC * ctx, const enet_uint8 * key, size_t keyLength)
{
    enet_uint8 keyBlock [64], innerPad [64];
    size_t i;

    memset (keyBlock, 0, sizeof (keyBlock));
    if (keyLength > sizeof (keyBlock))
      enet_sha256 (key, keyLength, keyBlock);
    else
      memcpy (keyBlock, key, keyLength);

    for (i = 0; i < sizeof (keyBlock); ++ i)
    {
        innerPad [i] = (enet_uint8) (keyBlock [i] ^ 0x36);
        ctx -> outerPad [i] = (enet_uint8) (keyBlock [i] ^ 0x5c);
    }

    enet_sha256_init (& ctx -> inner);
    enet_sha256_update (& ctx -> inner, innerPad, sizeof (innerPad));

    enet_crypto_memzero (keyBlock, sizeof (keyBlock));
    enet_crypto_memzero (innerPad, sizeof (innerPad));
}

static void
enet_hmac_update (ENetHMAC * ctx, const enet_uint8 * data, size_t length)
{
    enet_sha256_update (& ctx -> inner, data, length);
}

static void
enet_hmac_final (ENetHMAC * ctx, enet_uint8 mac [32])
{
    enet_uint8 innerDigest [32];
    ENetSHA256 outer;

    enet_sha256_final (& ctx -> inner, innerDigest);

    enet_sha256_init (& outer);
    enet_sha256_update (& outer, ctx -> outerPad, sizeof (ctx -> outerPad));
    enet_sha256_update (& outer, innerDigest, sizeof (innerDigest));
    enet_sha256_final (& outer, mac);

    enet_crypto_memzero (innerDigest, sizeof (innerDigest));
    enet_crypto_memzero (ctx, sizeof (* ctx));
}

void
enet_hmac_sha256 (const enet_uint8 * key, size_t keyLength, const enet_uint8 * data, size_t dataLength, enet_uint8 mac [32])
{
    ENetHMAC ctx;

    enet_hmac_init (& ctx, key, keyLength);
    enet_hmac_update (& ctx, data, dataLength);
    enet_hmac_final (& ctx, mac);
}

void
enet_hkdf_extract (const enet_uint8 * salt, size_t saltLength, const enet_uint8 * ikm, size_t ikmLength, enet_uint8 prk [32])
{
    enet_uint8 zeroSalt [32];

    if (salt == NULL || saltLength == 0)
    {
        memset (zeroSalt, 0, sizeof (zeroSalt));
        salt = zeroSalt;
        saltLength = sizeof (zeroSalt);
    }

    enet_hmac_sha256 (salt, saltLength, ikm, ikmLength, prk);
    enet_crypto_memzero (zeroSalt, sizeof (zeroSalt));
}

void
enet_hkdf_expand (const enet_uint8 prk [32], const enet_uint8 * info, size_t infoLength, enet_uint8 * out, size_t outLength)
{
    enet_uint8 t [32], counter;
    size_t tLength = 0, done = 0;

    for (counter = 1; done < outLength; ++ counter)
    {
        ENetHMAC ctx;
        size_t chunk;

        enet_hmac_init (& ctx, prk, 32);
        if (tLength > 0)
          enet_hmac_update (& ctx, t, tLength);
        if (info != NULL && infoLength > 0)
          enet_hmac_update (& ctx, info, infoLength);
        enet_hmac_update (& ctx, & counter, 1);
        enet_hmac_final (& ctx, t);
        tLength = sizeof (t);

        chunk = outLength - done;
        if (chunk > sizeof (t))
          chunk = sizeof (t);
        memcpy (out + done, t, chunk);
        done += chunk;
    }

    enet_crypto_memzero (t, sizeof (t));
}

/* ===================================================================== */
/* ChaCha20 (RFC 8439)                                                   */
/* ===================================================================== */

#define CHACHA_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define CHACHA_QUARTER_ROUND(s, a, b, c, d) \
    s [a] += s [b]; s [d] ^= s [a]; s [d] = CHACHA_ROTL (s [d], 16); \
    s [c] += s [d]; s [b] ^= s [c]; s [b] = CHACHA_ROTL (s [b], 12); \
    s [a] += s [b]; s [d] ^= s [a]; s [d] = CHACHA_ROTL (s [d], 8);  \
    s [c] += s [d]; s [b] ^= s [c]; s [b] = CHACHA_ROTL (s [b], 7);

static enet_uint32
enet_crypto_load32 (const enet_uint8 * p)
{
    return (enet_uint32) p [0] |
           ((enet_uint32) p [1] << 8) |
           ((enet_uint32) p [2] << 16) |
           ((enet_uint32) p [3] << 24);
}

static void
enet_crypto_chacha20_block (const enet_uint8 key [32], const enet_uint8 nonce [12], enet_uint32 counter, enet_uint8 out [64])
{
    enet_uint32 state [16], working [16];
    int i;

    state [0] = 0x61707865; state [1] = 0x3320646e;
    state [2] = 0x79622d32; state [3] = 0x6b206574;
    for (i = 0; i < 8; ++ i)
      state [4 + i] = enet_crypto_load32 (key + i * 4);
    state [12] = counter;
    state [13] = enet_crypto_load32 (nonce);
    state [14] = enet_crypto_load32 (nonce + 4);
    state [15] = enet_crypto_load32 (nonce + 8);

    memcpy (working, state, sizeof (state));

    for (i = 0; i < 10; ++ i)
    {
        CHACHA_QUARTER_ROUND (working, 0, 4, 8, 12)
        CHACHA_QUARTER_ROUND (working, 1, 5, 9, 13)
        CHACHA_QUARTER_ROUND (working, 2, 6, 10, 14)
        CHACHA_QUARTER_ROUND (working, 3, 7, 11, 15)
        CHACHA_QUARTER_ROUND (working, 0, 5, 10, 15)
        CHACHA_QUARTER_ROUND (working, 1, 6, 11, 12)
        CHACHA_QUARTER_ROUND (working, 2, 7, 8, 13)
        CHACHA_QUARTER_ROUND (working, 3, 4, 9, 14)
    }

    for (i = 0; i < 16; ++ i)
    {
        enet_uint32 word = working [i] + state [i];
        out [i * 4]     = (enet_uint8) word;
        out [i * 4 + 1] = (enet_uint8) (word >> 8);
        out [i * 4 + 2] = (enet_uint8) (word >> 16);
        out [i * 4 + 3] = (enet_uint8) (word >> 24);
    }

    enet_crypto_memzero (working, sizeof (working));
    enet_crypto_memzero (state, sizeof (state));
}

/* Encrypts/decrypts in place; data may be NULL when length is 0. */
void
enet_crypto_chacha20_xor (const enet_uint8 key [32], const enet_uint8 nonce [12], enet_uint32 counter, enet_uint8 * data, size_t length)
{
    enet_uint8 keystream [64];

    while (length > 0)
    {
        size_t i, chunk = length < sizeof (keystream) ? length : sizeof (keystream);

        enet_crypto_chacha20_block (key, nonce, counter, keystream);
        ++ counter;

        for (i = 0; i < chunk; ++ i)
          data [i] ^= keystream [i];

        data += chunk;
        length -= chunk;
    }

    enet_crypto_memzero (keystream, sizeof (keystream));
}

/* ===================================================================== */
/* Poly1305 (RFC 8439), 32-bit "donna" style                             */
/* ===================================================================== */

typedef struct _ENetPoly1305
{
   enet_uint32 r [5];
   enet_uint32 h [5];
   enet_uint32 pad [4];
   enet_uint8  buffer [16];
   size_t      bufferLength;
   int         final;
} ENetPoly1305;

static void
enet_poly1305_init (ENetPoly1305 * ctx, const enet_uint8 key [32])
{
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    ctx -> r [0] =  enet_crypto_load32 (key +  0)        & 0x3ffffff;
    ctx -> r [1] = (enet_crypto_load32 (key +  3) >> 2)  & 0x3ffff03;
    ctx -> r [2] = (enet_crypto_load32 (key +  6) >> 4)  & 0x3ffc0ff;
    ctx -> r [3] = (enet_crypto_load32 (key +  9) >> 6)  & 0x3f03fff;
    ctx -> r [4] = (enet_crypto_load32 (key + 12) >> 8)  & 0x00fffff;

    memset (ctx -> h, 0, sizeof (ctx -> h));

    ctx -> pad [0] = enet_crypto_load32 (key + 16);
    ctx -> pad [1] = enet_crypto_load32 (key + 20);
    ctx -> pad [2] = enet_crypto_load32 (key + 24);
    ctx -> pad [3] = enet_crypto_load32 (key + 28);

    ctx -> bufferLength = 0;
    ctx -> final = 0;
}

static void
enet_poly1305_blocks (ENetPoly1305 * ctx, const enet_uint8 * data, size_t length)
{
    const enet_uint32 hibit = ctx -> final ? 0 : (1u << 24);
    enet_uint32 r0 = ctx -> r [0], r1 = ctx -> r [1], r2 = ctx -> r [2],
                r3 = ctx -> r [3], r4 = ctx -> r [4];
    enet_uint32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    enet_uint32 h0 = ctx -> h [0], h1 = ctx -> h [1], h2 = ctx -> h [2],
                h3 = ctx -> h [3], h4 = ctx -> h [4];

    while (length >= 16)
    {
        enet_uint32 t0 = enet_crypto_load32 (data +  0),
                    t1 = enet_crypto_load32 (data +  4),
                    t2 = enet_crypto_load32 (data +  8),
                    t3 = enet_crypto_load32 (data + 12);
        enet_uint64 d0, d1, d2, d3, d4, c;

        h0 += t0 & 0x3ffffff;
        h1 += (enet_uint32) ((((enet_uint64) t1 << 32) | t0) >> 26) & 0x3ffffff;
        h2 += (enet_uint32) ((((enet_uint64) t2 << 32) | t1) >> 20) & 0x3ffffff;
        h3 += (enet_uint32) ((((enet_uint64) t3 << 32) | t2) >> 14) & 0x3ffffff;
        h4 += (t3 >> 8) | hibit;

        d0 = (enet_uint64) h0 * r0 + (enet_uint64) h1 * s4 + (enet_uint64) h2 * s3 + (enet_uint64) h3 * s2 + (enet_uint64) h4 * s1;
        d1 = (enet_uint64) h0 * r1 + (enet_uint64) h1 * r0 + (enet_uint64) h2 * s4 + (enet_uint64) h3 * s3 + (enet_uint64) h4 * s2;
        d2 = (enet_uint64) h0 * r2 + (enet_uint64) h1 * r1 + (enet_uint64) h2 * r0 + (enet_uint64) h3 * s4 + (enet_uint64) h4 * s3;
        d3 = (enet_uint64) h0 * r3 + (enet_uint64) h1 * r2 + (enet_uint64) h2 * r1 + (enet_uint64) h3 * r0 + (enet_uint64) h4 * s4;
        d4 = (enet_uint64) h0 * r4 + (enet_uint64) h1 * r3 + (enet_uint64) h2 * r2 + (enet_uint64) h3 * r1 + (enet_uint64) h4 * r0;

        c = (enet_uint32) (d0 >> 26); h0 = (enet_uint32) d0 & 0x3ffffff;
        d1 += c; c = (enet_uint32) (d1 >> 26); h1 = (enet_uint32) d1 & 0x3ffffff;
        d2 += c; c = (enet_uint32) (d2 >> 26); h2 = (enet_uint32) d2 & 0x3ffffff;
        d3 += c; c = (enet_uint32) (d3 >> 26); h3 = (enet_uint32) d3 & 0x3ffffff;
        d4 += c; c = (enet_uint32) (d4 >> 26); h4 = (enet_uint32) d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        data += 16;
        length -= 16;
    }

    ctx -> h [0] = h0; ctx -> h [1] = h1; ctx -> h [2] = h2;
    ctx -> h [3] = h3; ctx -> h [4] = h4;
}

static void
enet_poly1305_update (ENetPoly1305 * ctx, const enet_uint8 * data, size_t length)
{
    if (ctx -> bufferLength > 0)
    {
        size_t want = sizeof (ctx -> buffer) - ctx -> bufferLength;
        if (want > length)
          want = length;

        memcpy (ctx -> buffer + ctx -> bufferLength, data, want);
        ctx -> bufferLength += want;
        data += want;
        length -= want;

        if (ctx -> bufferLength == sizeof (ctx -> buffer))
        {
            enet_poly1305_blocks (ctx, ctx -> buffer, sizeof (ctx -> buffer));
            ctx -> bufferLength = 0;
        }
    }

    if (length >= 16)
    {
        size_t whole = length & ~ (size_t) 15;
        enet_poly1305_blocks (ctx, data, whole);
        data += whole;
        length -= whole;
    }

    if (length > 0)
    {
        memcpy (ctx -> buffer, data, length);
        ctx -> bufferLength = length;
    }
}

static void
enet_poly1305_pad (ENetPoly1305 * ctx)
{
    static const enet_uint8 zero [16] = { 0 };

    /* AEAD padding: zero-fill the current partial block to 16 bytes */
    if (ctx -> bufferLength > 0)
      enet_poly1305_update (ctx, zero, sizeof (ctx -> buffer) - ctx -> bufferLength);
}

static void
enet_poly1305_final (ENetPoly1305 * ctx, enet_uint8 tag [16])
{
    enet_uint32 h0, h1, h2, h3, h4, c;
    enet_uint32 g0, g1, g2, g3, g4;
    enet_uint64 f;
    enet_uint32 mask;

    if (ctx -> bufferLength > 0)
    {
        /* final partial block: append 0x01 and process without hibit */
        ctx -> buffer [ctx -> bufferLength ++] = 1;
        memset (ctx -> buffer + ctx -> bufferLength, 0, sizeof (ctx -> buffer) - ctx -> bufferLength);
        ctx -> final = 1;
        enet_poly1305_blocks (ctx, ctx -> buffer, sizeof (ctx -> buffer));
    }

    /* full carry */
    h0 = ctx -> h [0]; h1 = ctx -> h [1]; h2 = ctx -> h [2];
    h3 = ctx -> h [3]; h4 = ctx -> h [4];

    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    /* compute h + -p, select h if h < p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);

    mask = (g4 >> 31) - 1;   /* all ones if h < p (g4 wrapped), else 0 */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~ mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = (h0      ) | (h1 << 26);
    h1 = (h1 >>  6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 <<  8);

    /* tag = (h + pad) % 2^128 */
    f = (enet_uint64) h0 + ctx -> pad [0]; h0 = (enet_uint32) f;
    f = (enet_uint64) h1 + ctx -> pad [1] + (f >> 32); h1 = (enet_uint32) f;
    f = (enet_uint64) h2 + ctx -> pad [2] + (f >> 32); h2 = (enet_uint32) f;
    f = (enet_uint64) h3 + ctx -> pad [3] + (f >> 32); h3 = (enet_uint32) f;

    tag [ 0] = (enet_uint8) h0;        tag [ 1] = (enet_uint8) (h0 >> 8);
    tag [ 2] = (enet_uint8) (h0 >> 16); tag [ 3] = (enet_uint8) (h0 >> 24);
    tag [ 4] = (enet_uint8) h1;        tag [ 5] = (enet_uint8) (h1 >> 8);
    tag [ 6] = (enet_uint8) (h1 >> 16); tag [ 7] = (enet_uint8) (h1 >> 24);
    tag [ 8] = (enet_uint8) h2;        tag [ 9] = (enet_uint8) (h2 >> 8);
    tag [10] = (enet_uint8) (h2 >> 16); tag [11] = (enet_uint8) (h2 >> 24);
    tag [12] = (enet_uint8) h3;        tag [13] = (enet_uint8) (h3 >> 8);
    tag [14] = (enet_uint8) (h3 >> 16); tag [15] = (enet_uint8) (h3 >> 24);

    enet_crypto_memzero (ctx, sizeof (* ctx));
}

void
enet_crypto_poly1305 (const enet_uint8 * data, size_t length, const enet_uint8 key [32], enet_uint8 tag [16])
{
    ENetPoly1305 ctx;

    enet_poly1305_init (& ctx, key);
    enet_poly1305_update (& ctx, data, length);
    enet_poly1305_final (& ctx, tag);
}

/* ===================================================================== */
/* AEAD: ChaCha20-Poly1305 (RFC 8439 section 2.8)                        */
/* ===================================================================== */

static void
enet_crypto_aead_mac (const enet_uint8 oneTimeKey [32], const enet_uint8 * aad, size_t aadLength, const enet_uint8 * ciphertext, size_t ciphertextLength, enet_uint8 tag [16])
{
    ENetPoly1305 ctx;
    enet_uint8 lengths [16];
    enet_uint64 value;

    enet_poly1305_init (& ctx, oneTimeKey);
    enet_poly1305_update (& ctx, aad, aadLength);
    enet_poly1305_pad (& ctx);
    enet_poly1305_update (& ctx, ciphertext, ciphertextLength);
    enet_poly1305_pad (& ctx);

    value = (enet_uint64) aadLength;
    lengths [0] = (enet_uint8) value;        lengths [1] = (enet_uint8) (value >> 8);
    lengths [2] = (enet_uint8) (value >> 16); lengths [3] = (enet_uint8) (value >> 24);
    lengths [4] = (enet_uint8) (value >> 32); lengths [5] = (enet_uint8) (value >> 40);
    lengths [6] = (enet_uint8) (value >> 48); lengths [7] = (enet_uint8) (value >> 56);
    value = (enet_uint64) ciphertextLength;
    lengths [8] = (enet_uint8) value;         lengths [9] = (enet_uint8) (value >> 8);
    lengths [10] = (enet_uint8) (value >> 16); lengths [11] = (enet_uint8) (value >> 24);
    lengths [12] = (enet_uint8) (value >> 32); lengths [13] = (enet_uint8) (value >> 40);
    lengths [14] = (enet_uint8) (value >> 48); lengths [15] = (enet_uint8) (value >> 56);

    enet_poly1305_update (& ctx, lengths, sizeof (lengths));
    enet_poly1305_final (& ctx, tag);

    enet_crypto_memzero (lengths, sizeof (lengths));
}

/* Encrypts data in place and appends the tag into tag[16]. */
void
enet_crypto_aead_seal (const enet_uint8 key [32], const enet_uint8 nonce [12], const enet_uint8 * aad, size_t aadLength, enet_uint8 * data, size_t dataLength, enet_uint8 tag [16])
{
    enet_uint8 block [64], oneTimeKey [32];

    enet_crypto_chacha20_block (key, nonce, 0, block);
    memcpy (oneTimeKey, block, sizeof (oneTimeKey));
    enet_crypto_memzero (block, sizeof (block));

    enet_crypto_chacha20_xor (key, nonce, 1, data, dataLength);

    enet_crypto_aead_mac (oneTimeKey, aad, aadLength, data, dataLength, tag);

    enet_crypto_memzero (oneTimeKey, sizeof (oneTimeKey));
}

/* Verifies the tag and, only if valid, decrypts data in place.
   Returns 0 on success, < 0 on tag mismatch. */
int
enet_crypto_aead_open (const enet_uint8 key [32], const enet_uint8 nonce [12], const enet_uint8 * aad, size_t aadLength, enet_uint8 * data, size_t dataLength, const enet_uint8 tag [16])
{
    enet_uint8 block [64], oneTimeKey [32], computedTag [16];
    int valid;

    enet_crypto_chacha20_block (key, nonce, 0, block);
    memcpy (oneTimeKey, block, sizeof (oneTimeKey));
    enet_crypto_memzero (block, sizeof (block));

    enet_crypto_aead_mac (oneTimeKey, aad, aadLength, data, dataLength, computedTag);
    enet_crypto_memzero (oneTimeKey, sizeof (oneTimeKey));

    valid = enet_crypto_equal (computedTag, tag, ENET_CRYPTO_TAG_SIZE);
    enet_crypto_memzero (computedTag, sizeof (computedTag));

    if (! valid)
      return -1;

    enet_crypto_chacha20_xor (key, nonce, 1, data, dataLength);
    return 0;
}

/* ===================================================================== */
/* key schedule                                                          */
/* ===================================================================== */

static void
enet_crypto_derive_hs_key (const enet_uint8 psk [ENET_CRYPTO_KEY_SIZE], enet_uint8 out [ENET_CRYPTO_KEY_SIZE])
{
    static const enet_uint8 salt [] = "enet-crypto-v1-hs";
    enet_hkdf_extract (salt, sizeof (salt) - 1, psk, ENET_CRYPTO_KEY_SIZE, out);
}

static void
enet_crypto_derive_master (const enet_uint8 psk [ENET_CRYPTO_KEY_SIZE], const enet_uint8 clientNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], const enet_uint8 serverNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], enet_uint8 out [ENET_CRYPTO_KEY_SIZE])
{
    enet_uint8 salt [ENET_CRYPTO_NONCE_COUNT_SIZE * 2];

    memcpy (salt, clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
    memcpy (salt + ENET_CRYPTO_NONCE_COUNT_SIZE, serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
    enet_hkdf_extract (salt, sizeof (salt), psk, ENET_CRYPTO_KEY_SIZE, out);
    enet_crypto_memzero (salt, sizeof (salt));
}

/* direction: 0 = initiator -> responder, 1 = responder -> initiator */
static void
enet_crypto_derive_epoch_key (const enet_uint8 master [ENET_CRYPTO_KEY_SIZE], enet_uint8 direction, enet_uint16 epoch, enet_uint8 out [ENET_CRYPTO_KEY_SIZE])
{
    enet_uint8 info [sizeof ("enet-crypto-v1-key") - 1 + 3];
    size_t infoLength = 0;

    memcpy (info, "enet-crypto-v1-key", sizeof ("enet-crypto-v1-key") - 1);
    infoLength = sizeof ("enet-crypto-v1-key") - 1;
    info [infoLength ++] = direction;
    info [infoLength ++] = (enet_uint8) epoch;
    info [infoLength ++] = (enet_uint8) (epoch >> 8);

    enet_hkdf_expand (master, info, infoLength, out, ENET_CRYPTO_KEY_SIZE);
    enet_crypto_memzero (info, sizeof (info));
}

static enet_uint8
enet_crypto_send_direction (const ENetCryptoPeer * session)
{
    return (session -> flags & ENET_CRYPTO_PEER_IS_INITIATOR) ? 0 : 1;
}

static void
enet_crypto_derive_send_key (ENetCryptoPeer * session)
{
    enet_crypto_derive_epoch_key (session -> masterSecret, enet_crypto_send_direction (session), session -> sendEpoch, session -> sendKey);
}

static void
enet_crypto_derive_recv_key (ENetCryptoPeer * session, enet_uint16 epoch, enet_uint8 out [ENET_CRYPTO_KEY_SIZE])
{
    enet_crypto_derive_epoch_key (session -> masterSecret, (enet_uint8) (enet_crypto_send_direction (session) ^ 1), epoch, out);
}

static void
enet_crypto_derive_session (ENetCryptoPeer * session, const enet_uint8 psk [ENET_CRYPTO_KEY_SIZE])
{
    session -> sendEpoch = 0;
    session -> recvEpoch = 0;
    session -> sendSeq = 0;

    enet_crypto_derive_master (psk, session -> clientNonce, session -> serverNonce, session -> masterSecret);
    enet_crypto_derive_send_key (session);
    enet_crypto_derive_recv_key (session, 0, session -> recvKey [0]);

    session -> recvSlotEpoch [0] = 0;
    session -> recvSlotValid [0] = 1;
    session -> recvSlotValid [1] = 0;
    session -> recvSeqMax [0] = 0;
    session -> recvSeqMax [1] = 0;
    memset (session -> recvWindow, 0, sizeof (session -> recvWindow));

    session -> flags |= ENET_CRYPTO_PEER_RECV_READY;
}

/* ===================================================================== */
/* handshake                                                             */
/* ===================================================================== */

static void
enet_crypto_hs_mac (const enet_uint8 hsKey [ENET_CRYPTO_KEY_SIZE], const char * label, enet_uint32 connectID, const enet_uint8 * clientNonce, const enet_uint8 * serverNonce, enet_uint8 mac [ENET_CRYPTO_MAC_SIZE])
{
    ENetHMAC ctx;
    enet_uint8 full [32];
    enet_uint8 idLE [4];

    idLE [0] = (enet_uint8) connectID;
    idLE [1] = (enet_uint8) (connectID >> 8);
    idLE [2] = (enet_uint8) (connectID >> 16);
    idLE [3] = (enet_uint8) (connectID >> 24);

    enet_hmac_init (& ctx, hsKey, ENET_CRYPTO_KEY_SIZE);
    enet_hmac_update (& ctx, (const enet_uint8 *) label, strlen (label));
    enet_hmac_update (& ctx, idLE, sizeof (idLE));
    enet_hmac_update (& ctx, clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
    if (serverNonce != NULL)
      enet_hmac_update (& ctx, serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
    enet_hmac_final (& ctx, full);

    memcpy (mac, full, ENET_CRYPTO_MAC_SIZE);
    enet_crypto_memzero (full, sizeof (full));
}

/* Client side: generate and store the client nonce, output the HS_INIT MAC. */
void
enet_crypto_hs_init (ENetHost * host, ENetPeer * peer, enet_uint8 clientNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], enet_uint8 mac [ENET_CRYPTO_MAC_SIZE])
{
    ENetCryptoPeer * session = & peer -> crypto;
    enet_uint8 hsKey [ENET_CRYPTO_KEY_SIZE];

    enet_crypto_random (session -> clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
    session -> flags |= ENET_CRYPTO_PEER_IS_INITIATOR;

    memcpy (clientNonce, session -> clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);

    enet_crypto_derive_hs_key (host -> cryptoPsk, hsKey);
    enet_crypto_hs_mac (hsKey, "enet-hs-init", peer -> connectID, session -> clientNonce, NULL, mac);
    enet_crypto_memzero (hsKey, sizeof (hsKey));
}

/* Server side: validate HS_INIT, derive the session, output HS_REPLY fields.
   Returns 0 on success, 1 if this is a duplicate of an already-accepted
   INIT (outputs are refilled from the stored state), < 0 on failure. */
int
enet_crypto_hs_accept (ENetHost * host, ENetPeer * peer, const enet_uint8 clientNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], const enet_uint8 mac [ENET_CRYPTO_MAC_SIZE], enet_uint8 serverNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], enet_uint8 replyMac [ENET_CRYPTO_MAC_SIZE])
{
    ENetCryptoPeer * session = & peer -> crypto;
    enet_uint8 hsKey [ENET_CRYPTO_KEY_SIZE], expected [ENET_CRYPTO_MAC_SIZE];
    int result = 0;

    enet_crypto_derive_hs_key (host -> cryptoPsk, hsKey);
    enet_crypto_hs_mac (hsKey, "enet-hs-init", peer -> connectID, clientNonce, NULL, expected);

    if (! enet_crypto_equal (expected, mac, ENET_CRYPTO_MAC_SIZE))
    {
        enet_crypto_memzero (hsKey, sizeof (hsKey));
        enet_crypto_memzero (expected, sizeof (expected));
        return -1;
    }

    if (session -> flags & ENET_CRYPTO_PEER_RECV_READY)
    {
        /* retransmitted INIT: only the identical nonce is acceptable */
        if (! enet_crypto_equal (session -> clientNonce, clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE))
          result = -1;
        else
          result = 1;
    }

    if (result == 0)
    {
        memcpy (session -> clientNonce, clientNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
        enet_crypto_random (session -> serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
        session -> flags &= ~ ENET_CRYPTO_PEER_IS_INITIATOR;
        enet_crypto_derive_session (session, host -> cryptoPsk);
    }

    if (result >= 0)
    {
        memcpy (serverNonce, session -> serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
        enet_crypto_hs_mac (hsKey, "enet-hs-reply", peer -> connectID, session -> clientNonce, session -> serverNonce, replyMac);
    }

    enet_crypto_memzero (hsKey, sizeof (hsKey));
    enet_crypto_memzero (expected, sizeof (expected));

    return result;
}

/* Client side: validate HS_REPLY and derive the session.
   Returns 0 on success, 1 on duplicate, < 0 on failure. */
int
enet_crypto_hs_complete (ENetHost * host, ENetPeer * peer, const enet_uint8 serverNonce [ENET_CRYPTO_NONCE_COUNT_SIZE], const enet_uint8 mac [ENET_CRYPTO_MAC_SIZE])
{
    ENetCryptoPeer * session = & peer -> crypto;
    enet_uint8 hsKey [ENET_CRYPTO_KEY_SIZE], expected [ENET_CRYPTO_MAC_SIZE];
    int result = 0;

    if (! (session -> flags & ENET_CRYPTO_PEER_IS_INITIATOR))
      return -1;   /* we never sent an INIT */

    enet_crypto_derive_hs_key (host -> cryptoPsk, hsKey);
    enet_crypto_hs_mac (hsKey, "enet-hs-reply", peer -> connectID, session -> clientNonce, serverNonce, expected);

    if (! enet_crypto_equal (expected, mac, ENET_CRYPTO_MAC_SIZE))
    {
        enet_crypto_memzero (hsKey, sizeof (hsKey));
        enet_crypto_memzero (expected, sizeof (expected));
        return -1;
    }

    if (session -> flags & ENET_CRYPTO_PEER_RECV_READY)
    {
        if (! enet_crypto_equal (session -> serverNonce, serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE))
          result = -1;
        else
          result = 1;
    }

    if (result == 0)
    {
        memcpy (session -> serverNonce, serverNonce, ENET_CRYPTO_NONCE_COUNT_SIZE);
        enet_crypto_derive_session (session, host -> cryptoPsk);
    }

    enet_crypto_memzero (hsKey, sizeof (hsKey));
    enet_crypto_memzero (expected, sizeof (expected));

    return result;
}

/* ===================================================================== */
/* per-peer session management                                           */
/* ===================================================================== */

void
enet_crypto_peer_reset (ENetPeer * peer)
{
    enet_crypto_memzero (& peer -> crypto, sizeof (peer -> crypto));
}

void
enet_crypto_peer_activate_send (ENetPeer * peer)
{
    if (peer -> crypto.flags & ENET_CRYPTO_PEER_SEND_ACTIVE)
      return;

    peer -> crypto.flags |= ENET_CRYPTO_PEER_SEND_ACTIVE;

    /* reserve room for the crypto header + tag in every outgoing packet */
    if (peer -> mtu > ENET_CRYPTO_OVERHEAD)
      peer -> mtu -= ENET_CRYPTO_OVERHEAD;
}

/* ===================================================================== */
/* packet sealing / opening                                              */
/* ===================================================================== */

static void
enet_crypto_store16 (enet_uint8 * p, enet_uint16 v)
{
    p [0] = (enet_uint8) v;
    p [1] = (enet_uint8) (v >> 8);
}

static void
enet_crypto_store64 (enet_uint8 * p, enet_uint64 v)
{
    int i;
    for (i = 0; i < 8; ++ i)
      p [i] = (enet_uint8) (v >> (i * 8));
}

static enet_uint16
enet_crypto_load16 (const enet_uint8 * p)
{
    return (enet_uint16) (p [0] | ((enet_uint16) p [1] << 8));
}

static enet_uint64
enet_crypto_load64 (const enet_uint8 * p)
{
    enet_uint64 v = 0;
    int i;
    for (i = 7; i >= 0; -- i)
      v = (v << 8) | p [i];
    return v;
}

static void
enet_crypto_build_nonce (enet_uint16 epoch, enet_uint64 sequence, enet_uint8 nonce [ENET_CRYPTO_NONCE_SIZE])
{
    enet_crypto_store64 (nonce, sequence);
    enet_crypto_store16 (nonce + 8, epoch);
    nonce [10] = 0;
    nonce [11] = 0;
}

/* Seals one UDP packet's command region.
   aad = plaintext ENet protocol header; plaintext = command region;
   out receives cryptoHeader || ciphertext || tag.
   Returns the total output length, or < 0 on failure. */
int
enet_crypto_seal_packet (ENetHost * host, ENetPeer * peer, const enet_uint8 * aad, size_t aadLength, const enet_uint8 * plaintext, size_t plaintextLength, enet_uint8 * out, size_t outLimit)
{
    ENetCryptoPeer * session = & peer -> crypto;
    enet_uint8 aadBuffer [64], nonce [ENET_CRYPTO_NONCE_SIZE];
    size_t aadTotal;

    if (plaintextLength > outLimit || outLimit - plaintextLength < ENET_CRYPTO_OVERHEAD)
      return -1;

    if (session -> sendSeq >= ENET_CRYPTO_REKEY_SEQ)
      enet_peer_crypto_rekey (peer);

    /* crypto header: epoch || sequence */
    enet_crypto_store16 (out, session -> sendEpoch);
    enet_crypto_store64 (out + 2, session -> sendSeq);

    /* AAD = ENet header || crypto header */
    if (aadLength + ENET_CRYPTO_HEADER_SIZE > sizeof (aadBuffer))
      return -1;
    memcpy (aadBuffer, aad, aadLength);
    memcpy (aadBuffer + aadLength, out, ENET_CRYPTO_HEADER_SIZE);
    aadTotal = aadLength + ENET_CRYPTO_HEADER_SIZE;

    memcpy (out + ENET_CRYPTO_HEADER_SIZE, plaintext, plaintextLength);

    enet_crypto_build_nonce (session -> sendEpoch, session -> sendSeq, nonce);
    enet_crypto_aead_seal (session -> sendKey, nonce, aadBuffer, aadTotal,
                           out + ENET_CRYPTO_HEADER_SIZE, plaintextLength,
                           out + ENET_CRYPTO_HEADER_SIZE + plaintextLength);

    ++ session -> sendSeq;
    ++ host -> cryptoStats.packetsEncrypted;

    enet_crypto_memzero (aadBuffer, sizeof (aadBuffer));
    enet_crypto_memzero (nonce, sizeof (nonce));

    return (int) (ENET_CRYPTO_OVERHEAD + plaintextLength);
}

/* Replay window: returns 0 if (slot, seq) is acceptable and records it,
   < 0 if it is a replay/too old.  Must only be called AFTER the tag has
   been verified. */
static int
enet_crypto_replay_check (ENetCryptoPeer * session, int slot, enet_uint64 sequence)
{
    enet_uint64 * maxSeq = & session -> recvSeqMax [slot];
    enet_uint32 * window = session -> recvWindow [slot];

    if (sequence > * maxSeq)
    {
        enet_uint64 shift = sequence - * maxSeq;
        size_t i;

        if (shift >= ENET_CRYPTO_REPLAY_BITS)
          memset (window, 0, ENET_CRYPTO_REPLAY_WORDS * sizeof (enet_uint32));
        else
        {
            size_t wordShift = (size_t) (shift / 32);
            int bitShift = (int) (shift % 32);

            for (i = ENET_CRYPTO_REPLAY_WORDS; i -- > 0; )
            {
                enet_uint32 value = 0;
                if (i >= wordShift)
                {
                    value = window [i - wordShift];
                    if (bitShift > 0)
                    {
                        value <<= bitShift;
                        if (i > wordShift)
                          value |= window [i - wordShift - 1] >> (32 - bitShift);
                    }
                }
                window [i] = value;
            }
        }

        window [0] |= 1;
        * maxSeq = sequence;
        return 0;
    }

    {
        enet_uint64 diff = * maxSeq - sequence;

        if (diff >= ENET_CRYPTO_REPLAY_BITS)
          return -1;

        if (window [diff / 32] & (1u << (diff % 32)))
          return -1;

        window [diff / 32] |= 1u << (diff % 32);
    }

    return 0;
}

/* Opens one received UDP packet in place.
   packet = start of the ENet protocol header (also the AAD),
   headerLength = length of the plaintext ENet header,
   cryptoLength = bytes after the header (cryptoHeader || ct || tag).
   On success the plaintext commands sit at packet + headerLength and the
   plaintext command-region length is returned.  Returns < 0 on failure
   (statistics are bumped; the caller drops the packet). */
int
enet_crypto_open_packet (ENetHost * host, ENetPeer * peer, enet_uint8 * packet, size_t headerLength, size_t cryptoLength)
{
    ENetCryptoPeer * session = & peer -> crypto;
    enet_uint8 aadBuffer [64], nonce [ENET_CRYPTO_NONCE_SIZE];
    enet_uint8 * cryptoHeader, * ciphertext, * tag;
    enet_uint16 epoch;
    enet_uint64 sequence;
    size_t ciphertextLength, aadTotal;
    int slot, freshEpoch = 0;
    enet_uint8 newKey [ENET_CRYPTO_KEY_SIZE];
    const enet_uint8 * key;

    if (cryptoLength < ENET_CRYPTO_OVERHEAD)
    {
        ++ host -> cryptoStats.droppedTooShort;
        return -1;
    }

    cryptoHeader = packet + headerLength;
    ciphertext = cryptoHeader + ENET_CRYPTO_HEADER_SIZE;
    ciphertextLength = cryptoLength - ENET_CRYPTO_OVERHEAD;
    tag = ciphertext + ciphertextLength;

    epoch = enet_crypto_load16 (cryptoHeader);
    sequence = enet_crypto_load64 (cryptoHeader + 2);

    /* select the key for this epoch */
    if (epoch == session -> recvEpoch && session -> recvSlotValid [epoch & 1] && session -> recvSlotEpoch [epoch & 1] == epoch)
    {
        slot = epoch & 1;
        key = session -> recvKey [slot];
    }
    else
    if ((enet_uint16) (epoch - session -> recvEpoch) == 1)
    {
        /* next epoch: derive tentatively, commit only after the tag verifies */
        slot = epoch & 1;
        enet_crypto_derive_recv_key (session, epoch, newKey);
        key = newKey;
        freshEpoch = 1;
    }
    else
    if ((enet_uint16) (session -> recvEpoch - epoch) == 1 && session -> recvSlotValid [epoch & 1] && session -> recvSlotEpoch [epoch & 1] == epoch)
    {
        slot = epoch & 1;
        key = session -> recvKey [slot];
    }
    else
    {
        ++ host -> cryptoStats.droppedBadEpoch;
        return -1;
    }

    /* AAD = ENet header || crypto header */
    if (headerLength + ENET_CRYPTO_HEADER_SIZE > sizeof (aadBuffer))
    {
        ++ host -> cryptoStats.droppedTooShort;
        return -1;
    }
    memcpy (aadBuffer, packet, headerLength);
    memcpy (aadBuffer + headerLength, cryptoHeader, ENET_CRYPTO_HEADER_SIZE);
    aadTotal = headerLength + ENET_CRYPTO_HEADER_SIZE;

    enet_crypto_build_nonce (epoch, sequence, nonce);

    if (enet_crypto_aead_open (key, nonce, aadBuffer, aadTotal, ciphertext, ciphertextLength, tag) < 0)
    {
        ++ host -> cryptoStats.droppedBadTag;
        enet_crypto_memzero (newKey, sizeof (newKey));
        enet_crypto_memzero (aadBuffer, sizeof (aadBuffer));
        enet_crypto_memzero (nonce, sizeof (nonce));
        return -1;
    }

    /* tag verified: commit epoch advancement and check the replay window */
    if (freshEpoch)
    {
        /* the overwritten slot held the oldest epoch; the other slot keeps
           the (now previous) epoch so stragglers still decrypt */
        memcpy (session -> recvKey [slot], newKey, ENET_CRYPTO_KEY_SIZE);
        session -> recvSlotEpoch [slot] = epoch;
        session -> recvSlotValid [slot] = 1;
        session -> recvSeqMax [slot] = 0;
        memset (session -> recvWindow [slot], 0, ENET_CRYPTO_REPLAY_WORDS * sizeof (enet_uint32));
        session -> recvEpoch = epoch;
    }

    if (enet_crypto_replay_check (session, slot, sequence) < 0)
    {
        ++ host -> cryptoStats.droppedReplay;
        enet_crypto_memzero (newKey, sizeof (newKey));
        enet_crypto_memzero (aadBuffer, sizeof (aadBuffer));
        enet_crypto_memzero (nonce, sizeof (nonce));
        return -1;
    }

    /* move the plaintext down over the crypto header */
    if (ciphertextLength > 0)
      memmove (cryptoHeader, ciphertext, ciphertextLength);

    ++ host -> cryptoStats.packetsDecrypted;

    enet_crypto_memzero (newKey, sizeof (newKey));
    enet_crypto_memzero (aadBuffer, sizeof (aadBuffer));
    enet_crypto_memzero (nonce, sizeof (nonce));

    return (int) ciphertextLength;
}

/* ===================================================================== */
/* public API                                                            */
/* ===================================================================== */

int
enet_host_crypto_set (ENetHost * host, const ENetCryptoConfig * config)
{
    if (host == NULL || config == NULL || config -> psk == NULL ||
        config -> pskLength != ENET_CRYPTO_KEY_SIZE)
      return -1;

    memcpy (host -> cryptoPsk, config -> psk, ENET_CRYPTO_KEY_SIZE);
    memset (& host -> cryptoStats, 0, sizeof (host -> cryptoStats));
    host -> cryptoEnabled = 1;

    return 0;
}

void
enet_host_crypto_clear (ENetHost * host)
{
    if (host == NULL)
      return;

    host -> cryptoEnabled = 0;
    enet_crypto_memzero (host -> cryptoPsk, sizeof (host -> cryptoPsk));
}

int
enet_peer_crypto_rekey (ENetPeer * peer)
{
    ENetCryptoPeer * session;

    if (peer == NULL || peer -> host == NULL || ! peer -> host -> cryptoEnabled)
      return -1;

    session = & peer -> crypto;
    if (! (session -> flags & ENET_CRYPTO_PEER_RECV_READY))
      return -1;

    ++ session -> sendEpoch;
    session -> sendSeq = 0;
    enet_crypto_derive_send_key (session);

    ++ peer -> host -> cryptoStats.rekeys;

    return 0;
}

int
enet_peer_crypto_established (const ENetPeer * peer)
{
    if (peer == NULL)
      return 0;

    return (peer -> crypto.flags & ENET_CRYPTO_PEER_RECV_READY) != 0;
}
