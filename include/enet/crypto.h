/**
 @file  crypto.h
 @brief Optional packet-level AEAD encryption for ENet.

 This module adds OPTIONAL packet-level confidentiality and integrity to
 ENet.  It is disabled by default; when disabled the wire format and all
 behavior are byte-identical to a build without this module.

 Features:
   - ChaCha20-Poly1305 (RFC 8439) authenticated encryption of everything
     after the plaintext ENet protocol header (the header is authenticated
     as additional data).
   - PSK-authenticated handshake (ephemeral random nonces + HKDF) that
     negotiates fresh per-connection, per-direction keys.
   - Per-packet sequence numbers with a sliding replay window.
   - Epoch-based key rotation (enet_peer_crypto_rekey).
   - Fail-open-free failure handling: every cryptographic failure drops
     the offending packet and bumps a counter in ENetCryptoStats; a
     legitimate connection is never torn down because of bad packets.

 Enabling crypto on a host makes it REQUIRED for all of that host's
 peers: a crypto-enabled host never completes a handshake with a peer
 that does not negotiate crypto (this is what prevents downgrade
 attacks).  Both sides must be configured with the same 32-byte
 pre-shared key via enet_host_crypto_set() before connecting.

 Notes:
   - No heap allocation is performed on the per-packet path.
   - Key material is never logged and is securely zeroed when a peer is
     reset or a host is destroyed/cleared.
   - When crypto is active for a peer, the host checksum callback is not
     applied to that peer's packets (the AEAD tag is strictly stronger).
*/
#ifndef __ENET_CRYPTO_H__
#define __ENET_CRYPTO_H__

#include "enet/types.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned long long enet_uint64;

#define ENET_CRYPTO_KEY_SIZE          32
#define ENET_CRYPTO_NONCE_SIZE        12
#define ENET_CRYPTO_TAG_SIZE          16
#define ENET_CRYPTO_NONCE_COUNT_SIZE  32   /* handshake nonce length */
#define ENET_CRYPTO_MAC_SIZE          16   /* truncated handshake MAC */

/* on the wire: u16 epoch (LE) || u64 sequence (LE) */
#define ENET_CRYPTO_HEADER_SIZE       10
#define ENET_CRYPTO_OVERHEAD          (ENET_CRYPTO_HEADER_SIZE + ENET_CRYPTO_TAG_SIZE)

#define ENET_CRYPTO_REPLAY_BITS       256
#define ENET_CRYPTO_REPLAY_WORDS      (ENET_CRYPTO_REPLAY_BITS / 32)

#define ENET_CRYPTO_HANDSHAKE_VERSION 1

/* automatically rotate the send key before the sequence space runs out */
#define ENET_CRYPTO_REKEY_SEQ         0xFFFFFFFFFFFF0000ULL

typedef enum _ENetCryptoHandshakeType
{
   ENET_CRYPTO_HANDSHAKE_INIT  = 1,
   ENET_CRYPTO_HANDSHAKE_REPLY = 2
} ENetCryptoHandshakeType;

typedef enum _ENetCryptoPeerFlag
{
   ENET_CRYPTO_PEER_RECV_READY      = (1 << 0),  /* session keys derived; can decrypt        */
   ENET_CRYPTO_PEER_SEND_ACTIVE     = (1 << 1),  /* outgoing packets are encrypted           */
   ENET_CRYPTO_PEER_VERIFY_RECEIVED = (1 << 2),  /* client: VERIFY_CONNECT seen, awaiting HS */
   ENET_CRYPTO_PEER_IS_INITIATOR    = (1 << 3)   /* this side sent HS_INIT (the "client")    */
} ENetCryptoPeerFlag;

/** Counters for cryptographic packet processing.  All failures are
  * accounted here; packets that fail are silently dropped. */
typedef struct _ENetCryptoStats
{
   enet_uint64 packetsEncrypted;    /* packets successfully sealed                  */
   enet_uint64 packetsDecrypted;    /* packets successfully verified + opened       */
   enet_uint64 droppedTooShort;     /* encrypted packet shorter than the overhead   */
   enet_uint64 droppedBadTag;       /* AEAD tag verification failed (tamper/wrong key) */
   enet_uint64 droppedReplay;       /* sequence number outside/seen in replay window */
   enet_uint64 droppedBadEpoch;     /* epoch too old or too far in the future       */
   enet_uint64 droppedPlaintext;    /* plaintext command not allowed before keys    */
   enet_uint64 handshakesCompleted; /* successful crypto handshakes                 */
   enet_uint64 handshakeFailures;   /* bad MAC, bad version, bad state, ...         */
   enet_uint64 rekeys;              /* local send-key rotations                     */
} ENetCryptoStats;

/** Configuration for enet_host_crypto_set(). */
typedef struct _ENetCryptoConfig
{
   const enet_uint8 * psk;        /* pre-shared key, must be ENET_CRYPTO_KEY_SIZE bytes */
   size_t             pskLength;
} ENetCryptoConfig;

/** Per-peer crypto session state (embedded in ENetPeer; internal use). */
typedef struct _ENetCryptoPeer
{
   enet_uint8    flags;                                   /* ENetCryptoPeerFlag bits      */
   enet_uint8    recvSlotValid[2];                        /* ring of recv epochs          */
   enet_uint16   sendEpoch;
   enet_uint16   recvEpoch;
   enet_uint16   recvSlotEpoch[2];
   enet_uint16   reserved;
   enet_uint64   sendSeq;
   enet_uint64   recvSeqMax[2];
   enet_uint32   recvWindow[2][ENET_CRYPTO_REPLAY_WORDS]; /* replay bitmaps per epoch     */
   enet_uint8    clientNonce[ENET_CRYPTO_NONCE_COUNT_SIZE];
   enet_uint8    serverNonce[ENET_CRYPTO_NONCE_COUNT_SIZE];
   enet_uint8    masterSecret[ENET_CRYPTO_KEY_SIZE];
   enet_uint8    sendKey[ENET_CRYPTO_KEY_SIZE];
   enet_uint8    recvKey[2][ENET_CRYPTO_KEY_SIZE];
} ENetCryptoPeer;

struct _ENetHost;
struct _ENetPeer;

/** Enables (and requires) packet crypto on a host.  Must be called before
  * any connection is made/accepted.  Returns 0 on success, < 0 on bad args.
  * The key is copied; the caller remains responsible for their own buffer. */
ENET_API int  enet_host_crypto_set (struct _ENetHost *, const ENetCryptoConfig *);

/** Disables crypto on a host and securely erases the stored PSK.  Peers
  * that already negotiated crypto keep their sessions until reset. */
ENET_API void enet_host_crypto_clear (struct _ENetHost *);

/** Rotates the local send key to the next epoch.  The peer transparently
  * follows on the first packet of the new epoch; packets of the previous
  * epoch remain acceptable.  Returns 0 on success, < 0 if crypto is not
  * established on this peer. */
ENET_API int  enet_peer_crypto_rekey (struct _ENetPeer *);

/** Returns non-zero if the crypto handshake completed for this peer. */
ENET_API int  enet_peer_crypto_established (const struct _ENetPeer *);

/** @defgroup crypto_private internal routines (also used by the test suite)
    @{ */
void enet_crypto_memzero (void *, size_t);
int  enet_crypto_equal (const void *, const void *, size_t);
int  enet_crypto_random (enet_uint8 *, size_t);

void enet_sha256 (const enet_uint8 *, size_t, enet_uint8 [32]);
void enet_hmac_sha256 (const enet_uint8 *, size_t, const enet_uint8 *, size_t, enet_uint8 [32]);
void enet_hkdf_extract (const enet_uint8 *, size_t, const enet_uint8 *, size_t, enet_uint8 [32]);
void enet_hkdf_expand (const enet_uint8 [32], const enet_uint8 *, size_t, enet_uint8 *, size_t);

void enet_crypto_chacha20_xor (const enet_uint8 [32], const enet_uint8 [12], enet_uint32, enet_uint8 *, size_t);
void enet_crypto_poly1305 (const enet_uint8 *, size_t, const enet_uint8 [32], enet_uint8 [16]);
void enet_crypto_aead_seal (const enet_uint8 [32], const enet_uint8 [12], const enet_uint8 *, size_t, enet_uint8 *, size_t, enet_uint8 [16]);
int  enet_crypto_aead_open (const enet_uint8 [32], const enet_uint8 [12], const enet_uint8 *, size_t, enet_uint8 *, size_t, const enet_uint8 [16]);

void enet_crypto_peer_reset (struct _ENetPeer *);

void enet_crypto_hs_init (struct _ENetHost *, struct _ENetPeer *, enet_uint8 [32], enet_uint8 [16]);
int  enet_crypto_hs_accept (struct _ENetHost *, struct _ENetPeer *, const enet_uint8 [32], const enet_uint8 [16], enet_uint8 [32], enet_uint8 [16]);
int  enet_crypto_hs_complete (struct _ENetHost *, struct _ENetPeer *, const enet_uint8 [32], const enet_uint8 [16]);

void enet_crypto_peer_activate_send (struct _ENetPeer *);
int  enet_crypto_seal_packet (struct _ENetHost *, struct _ENetPeer *, const enet_uint8 *, size_t, const enet_uint8 *, size_t, enet_uint8 *, size_t);
int  enet_crypto_open_packet (struct _ENetHost *, struct _ENetPeer *, enet_uint8 *, size_t, size_t);
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* __ENET_CRYPTO_H__ */
