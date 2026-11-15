/**
 @file  test_crypto_vectors.c
 @brief Known-answer tests for the primitives in crypto.c:
        SHA-256, HMAC-SHA256 (RFC 4231), HKDF (RFC 5869),
        ChaCha20 (RFC 8439 A.1), Poly1305 (RFC 8439 2.5.2),
        AEAD-ChaCha20-Poly1305 (RFC 8439 2.8.2).
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <enet/enet.h>
#include <enet/crypto.h>

static int failures = 0;

static int
hexval (char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t
unhex (const char * hex, enet_uint8 * out, size_t outLimit)
{
    size_t length = 0;

    while (hex [0] && hex [1] && length < outLimit)
    {
        out [length ++] = (enet_uint8) (hexval (hex [0]) * 16 + hexval (hex [1]));
        hex += 2;
    }
    return length;
}

static void
check (const char * name, const enet_uint8 * got, const enet_uint8 * want, size_t length)
{
    if (memcmp (got, want, length) != 0)
    {
        size_t i;
        printf ("FAIL: %s\n  got  ", name);
        for (i = 0; i < length && i < 32; ++ i) printf ("%02x", got [i]);
        printf ("\n  want ");
        for (i = 0; i < length && i < 32; ++ i) printf ("%02x", want [i]);
        printf ("\n");
        ++ failures;
    }
    else
      printf ("ok: %s\n", name);
}

static void
test_sha256 (void)
{
    enet_uint8 digest [32], want [32];

    enet_sha256 ((const enet_uint8 *) "abc", 3, digest);
    unhex ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, sizeof (want));
    check ("sha256(abc)", digest, want, 32);

    enet_sha256 ((const enet_uint8 *) "", 0, digest);
    unhex ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", want, sizeof (want));
    check ("sha256(empty)", digest, want, 32);

    enet_sha256 ((const enet_uint8 *) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
    unhex ("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", want, sizeof (want));
    check ("sha256(56-byte)", digest, want, 32);
}

static void
test_hmac (void)
{
    enet_uint8 key [136], data [128], mac [32], want [32];
    size_t keyLength, dataLength;

    /* RFC 4231 test case 1 */
    memset (key, 0x0b, 20);
    keyLength = 20;
    dataLength = (size_t) snprintf ((char *) data, sizeof (data), "Hi There");
    enet_hmac_sha256 (key, keyLength, data, dataLength, mac);
    unhex ("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, sizeof (want));
    check ("hmac-sha256 rfc4231#1", mac, want, 32);

    /* RFC 4231 test case 2 */
    keyLength = (size_t) snprintf ((char *) key, sizeof (key), "Jefe");
    dataLength = (size_t) snprintf ((char *) data, sizeof (data), "what do ya want for nothing?");
    enet_hmac_sha256 (key, keyLength, data, dataLength, mac);
    unhex ("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", want, sizeof (want));
    check ("hmac-sha256 rfc4231#2", mac, want, 32);

    /* RFC 4231 test case 6 (key longer than block size) */
    memset (key, 0xaa, 131);
    keyLength = 131;
    dataLength = (size_t) snprintf ((char *) data, sizeof (data), "Test Using Larger Than Block-Size Key - Hash Key First");
    enet_hmac_sha256 (key, keyLength, data, dataLength, mac);
    unhex ("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", want, sizeof (want));
    check ("hmac-sha256 rfc4231#6", mac, want, 32);
}

static void
test_hkdf (void)
{
    enet_uint8 ikm [22], salt [13], info [10], prk [32], okm [42], want [42];

    /* RFC 5869 test case 1 */
    memset (ikm, 0x0b, sizeof (ikm));
    unhex ("000102030405060708090a0b0c", salt, sizeof (salt));
    unhex ("f0f1f2f3f4f5f6f7f8f9", info, sizeof (info));

    enet_hkdf_extract (salt, sizeof (salt), ikm, sizeof (ikm), prk);
    unhex ("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", want, 32);
    check ("hkdf-extract rfc5869#1", prk, want, 32);

    enet_hkdf_expand (prk, info, sizeof (info), okm, sizeof (okm));
    unhex ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", want, sizeof (want));
    check ("hkdf-expand rfc5869#1", okm, want, 42);
}

static void
test_chacha20 (void)
{
    enet_uint8 key [32], nonce [12], data [64], want [64];

    /* RFC 8439 A.1 test vector #1: encrypt 64 zero bytes, counter 1 */
    unhex ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, sizeof (key));
    unhex ("000000090000004a00000000", nonce, sizeof (nonce));
    memset (data, 0, sizeof (data));

    enet_crypto_chacha20_xor (key, nonce, 1, data, sizeof (data));
    unhex ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
           "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", want, sizeof (want));
    check ("chacha20 rfc8439 A.1#1", data, want, 64);

    /* round-trip on a non-block-aligned length */
    {
        enet_uint8 msg [100];
        size_t i;
        for (i = 0; i < sizeof (msg); ++ i) msg [i] = (enet_uint8) i;
        enet_crypto_chacha20_xor (key, nonce, 7, msg, sizeof (msg));
        enet_crypto_chacha20_xor (key, nonce, 7, msg, sizeof (msg));
        {
            enet_uint8 expect [100];
            for (i = 0; i < sizeof (expect); ++ i) expect [i] = (enet_uint8) i;
            check ("chacha20 round-trip", msg, expect, sizeof (msg));
        }
    }
}

static void
test_poly1305 (void)
{
    enet_uint8 key [32], tag [16], want [16];
    const char * msg = "Cryptographic Forum Research Group";

    /* RFC 8439 section 2.5.2 */
    unhex ("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", key, sizeof (key));
    enet_crypto_poly1305 ((const enet_uint8 *) msg, strlen (msg), key, tag);
    unhex ("a8061dc1305136c6c22b8baf0c0127a9", want, sizeof (want));
    check ("poly1305 rfc8439 2.5.2", tag, want, 16);
}

static void
test_aead (void)
{
    enet_uint8 key [32], nonce [12], aad [12], tag [16], wantTag [16];
    enet_uint8 text [128], want [128];
    size_t textLength;
    const char * plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";

    /* RFC 8439 section 2.8.2 */
    unhex ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, sizeof (key));
    unhex ("070000004041424344454647", nonce, sizeof (nonce));
    unhex ("50515253c0c1c2c3c4c5c6c7", aad, sizeof (aad));

    textLength = strlen (plaintext);
    memcpy (text, plaintext, textLength);

    enet_crypto_aead_seal (key, nonce, aad, sizeof (aad), text, textLength, tag);

    unhex ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
           "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
           "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
           "3ff4def08e4b7a9de576d26586cec64b6116", want, (size_t) textLength);
    check ("aead rfc8439 2.8.2 ciphertext", text, want, (size_t) textLength);

    unhex ("1ae10b594f09e26a7e902ecbd0600691", wantTag, sizeof (wantTag));
    check ("aead rfc8439 2.8.2 tag", tag, wantTag, 16);

    /* decrypt in place and compare */
    if (enet_crypto_aead_open (key, nonce, aad, sizeof (aad), text, textLength, tag) != 0)
    {
        printf ("FAIL: aead open of valid packet rejected\n");
        ++ failures;
    }
    else
      check ("aead open round-trip", text, (const enet_uint8 *) plaintext, textLength);

    /* flip a bit: must be rejected */
    text [0] ^= 1;
    if (enet_crypto_aead_open (key, nonce, aad, sizeof (aad), text, textLength, tag) == 0)
    {
        printf ("FAIL: aead open accepted tampered ciphertext\n");
        ++ failures;
    }
    else
      printf ("ok: aead tamper rejected\n");

    /* truncated tag must be rejected */
    {
        enet_uint8 badTag [16];
        memcpy (badTag, tag, sizeof (badTag));
        badTag [15] ^= 0x80;
        if (enet_crypto_aead_open (key, nonce, aad, sizeof (aad), text, textLength, badTag) == 0)
        {
            printf ("FAIL: aead open accepted bad tag\n");
            ++ failures;
        }
        else
          printf ("ok: aead bad tag rejected\n");
    }
}

int
main (void)
{
    test_sha256 ();
    test_hmac ();
    test_hkdf ();
    test_chacha20 ();
    test_poly1305 ();
    test_aead ();

    if (failures > 0)
    {
        printf ("crypto vectors: %d FAILURES\n", failures);
        return 1;
    }

    printf ("crypto vectors: all tests passed\n");
    return 0;
}
