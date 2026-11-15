/**
 @file  test_crypto_integration.c
 @brief Live loopback tests for ENet's optional packet crypto:
        handshake, echo over multiple channels, replay, tamper, truncation,
        wrong key, downgrade (both directions), MITM handshake replacement,
        key rotation (incl. old-epoch straggler), reconnect, and a
        default-off wire-format regression.

        A small UDP proxy sits between client and server for the tests
        that need to observe/modify/replay datagrams.

        Note: this ENet version is IPv4-only (ENetAddress.host is 32 bits),
        so the loopback tests run on 127.0.0.1; the crypto layer itself is
        transport/address-family agnostic.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <enet/enet.h>
#include <enet/crypto.h>

#define SERVER_PORT_BASE  15780
#define PROXY_PORT_BASE   16880

static const enet_uint8 PSK_A [ENET_CRYPTO_KEY_SIZE] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const enet_uint8 PSK_B [ENET_CRYPTO_KEY_SIZE] =
{
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0
};

static int failures = 0;

#define CHECK(cond) do { \
    if (! (cond)) { \
        printf ("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        ++ failures; \
    } \
} while (0)

/* ------------------------------------------------------------------ */
/* test peer bookkeeping                                               */
/* ------------------------------------------------------------------ */

typedef struct _Side
{
   ENetHost *   host;
   ENetPeer *   peer;          /* client: outgoing peer; server: peer from CONNECT event */
   int          connected;
   int          disconnected;
   int          received;      /* number of messages received */
   enet_uint64  xorSum;        /* xor of all payload bytes, for content checks */
   int          channelCount [8];
   enet_uint32  connectData;
} Side;

static void
side_reset (Side * side)
{
    memset (side, 0, sizeof (* side));
}

static void
side_service (Side * side, enet_uint32 timeout)
{
    ENetEvent event;

    while (enet_host_service (side -> host, & event, timeout) > 0)
    {
        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            side -> connected = 1;
            side -> peer = event.peer;
            side -> connectData = event.data;
            break;

        case ENET_EVENT_TYPE_DISCONNECT:
            side -> disconnected = 1;
            side -> peer = NULL;
            break;

        case ENET_EVENT_TYPE_RECEIVE:
        {
            size_t i;
            ++ side -> received;
            if (event.channelID < 8)
              ++ side -> channelCount [event.channelID];
            for (i = 0; i < event.packet -> dataLength; ++ i)
              side -> xorSum ^= event.packet -> data [i];
            enet_packet_destroy (event.packet);
            break;
        }

        default:
            break;
        }
        timeout = 0;
    }
}

/* ------------------------------------------------------------------ */
/* UDP proxy                                                           */
/* ------------------------------------------------------------------ */

enum
{
    PROXY_FORWARD = 0,
    PROXY_DROP,
    PROXY_DUPLICATE,
    PROXY_HOLD
};

typedef struct _Proxy
{
   ENetSocket  socket;
   ENetAddress address;        /* where the proxy listens (client connects here) */
   ENetAddress serverAddress;
   ENetAddress clientAddress;  /* learned from the first client packet */
   enet_uint8  buffer [2048];
   /* packet inspection hooks */
   int       (* onPacket) (struct _Proxy *, enet_uint8 *, int, int);
   void *      hookData;
   /* held packet storage (PROXY_HOLD) */
   int         haveHeld;
   int         heldFromClient;
   int         heldLength;
   enet_uint8  held [2048];
   /* observation */
   int         clientPacketLengths [64];
   int         clientPacketCount;
} Proxy;

static int
proxy_init (Proxy * proxy, enet_uint16 proxyPort, enet_uint16 serverPort)
{
    memset (proxy, 0, sizeof (* proxy));

    proxy -> socket = enet_socket_create (ENET_SOCKET_TYPE_DATAGRAM);
    if (proxy -> socket == ENET_SOCKET_NULL)
      return -1;

    proxy -> address.host = ENET_HOST_ANY;
    proxy -> address.port = proxyPort;
    if (enet_socket_bind (proxy -> socket, & proxy -> address) < 0)
      return -1;

    enet_socket_set_option (proxy -> socket, ENET_SOCKOPT_NONBLOCK, 1);

    proxy -> serverAddress.host = ENET_HOST_ANY;
    enet_address_set_host_ip (& proxy -> serverAddress, "127.0.0.1");
    proxy -> serverAddress.port = serverPort;
    return 0;
}

static void
proxy_destroy (Proxy * proxy)
{
    enet_socket_destroy (proxy -> socket);
}

static void
proxy_send_to (Proxy * proxy, const ENetAddress * dest, const enet_uint8 * data, int length)
{
    ENetBuffer buffer;

    buffer.data = (void *) data;
    buffer.dataLength = (size_t) length;
    enet_socket_send (proxy -> socket, dest, & buffer, 1);
}

static void
proxy_pump (Proxy * proxy)
{
    for (;;)
    {
        ENetAddress from;
        ENetBuffer buffer;
        int length, fromServer, action = PROXY_FORWARD;
        const ENetAddress * dest;

        buffer.data = proxy -> buffer;
        buffer.dataLength = sizeof (proxy -> buffer);

        length = enet_socket_receive (proxy -> socket, & from, & buffer, 1);
        if (length <= 0)
          break;

        fromServer = (from.host == proxy -> serverAddress.host &&
                      from.port == proxy -> serverAddress.port);
        if (! fromServer)
        {
            proxy -> clientAddress = from;
            if (proxy -> clientPacketCount < 64)
              proxy -> clientPacketLengths [proxy -> clientPacketCount ++] = length;
        }
        else
        if (proxy -> clientAddress.port == 0)
          continue;   /* don't know where the client is yet */

        if (proxy -> onPacket != NULL)
          action = proxy -> onPacket (proxy, proxy -> buffer, length, ! fromServer);

        dest = fromServer ? & proxy -> clientAddress : & proxy -> serverAddress;

        switch (action)
        {
        case PROXY_DROP:
            break;

        case PROXY_DUPLICATE:
            proxy_send_to (proxy, dest, proxy -> buffer, length);
            proxy_send_to (proxy, dest, proxy -> buffer, length);
            break;

        case PROXY_HOLD:
            if (length <= (int) sizeof (proxy -> held))
            {
                memcpy (proxy -> held, proxy -> buffer, (size_t) length);
                proxy -> heldLength = length;
                proxy -> heldFromClient = ! fromServer;
                proxy -> haveHeld = 1;
            }
            break;

        default:
            proxy_send_to (proxy, dest, proxy -> buffer, length);
            break;
        }
    }
}

static void
proxy_inject_held (Proxy * proxy)
{
    if (! proxy -> haveHeld)
      return;

    proxy_send_to (proxy,
                   proxy -> heldFromClient ? & proxy -> serverAddress : & proxy -> clientAddress,
                   proxy -> held, proxy -> heldLength);
    proxy -> haveHeld = 0;
}

/* ------------------------------------------------------------------ */
/* harness                                                             */
/* ------------------------------------------------------------------ */

typedef struct _Fixture
{
   Side    client;
   Side    server;
   Proxy   proxy;
   int     useProxy;
   ENetAddress serverAddress;   /* real server address */
   ENetAddress connectAddress;  /* where the client connects (proxy or server) */
} Fixture;

static enet_uint16 testNumber = 0;

static int
fixture_init (Fixture * fx, int cryptoClient, int cryptoServer, int useProxy, size_t channelCount)
{
    ENetAddress address;
    enet_uint16 serverPort = (enet_uint16) (SERVER_PORT_BASE + testNumber * 2),
                proxyPort  = (enet_uint16) (PROXY_PORT_BASE + testNumber * 2);
    ENetCryptoConfig config;

    ++ testNumber;

    memset (fx, 0, sizeof (* fx));
    side_reset (& fx -> client);
    side_reset (& fx -> server);
    fx -> useProxy = useProxy;

    address.host = ENET_HOST_ANY;
    address.port = serverPort;
    fx -> server.host = enet_host_create (& address, 8, channelCount, 0, 0);
    if (fx -> server.host == NULL)
      return -1;

    fx -> client.host = enet_host_create (NULL, 8, channelCount, 0, 0);
    if (fx -> client.host == NULL)
      return -1;

    if (cryptoServer)
    {
        config.psk = PSK_A;
        config.pskLength = ENET_CRYPTO_KEY_SIZE;
        if (enet_host_crypto_set (fx -> server.host, & config) != 0)
          return -1;
    }
    if (cryptoClient)
    {
        config.psk = PSK_A;
        config.pskLength = ENET_CRYPTO_KEY_SIZE;
        if (enet_host_crypto_set (fx -> client.host, & config) != 0)
          return -1;
    }

    fx -> serverAddress.host = ENET_HOST_ANY;
    enet_address_set_host_ip (& fx -> serverAddress, "127.0.0.1");
    fx -> serverAddress.port = serverPort;

    fx -> connectAddress = fx -> serverAddress;

    if (useProxy)
    {
        if (proxy_init (& fx -> proxy, proxyPort, serverPort) < 0)
          return -1;
        fx -> connectAddress.port = proxyPort;
    }

    return 0;
}

static void
fixture_destroy (Fixture * fx)
{
    if (fx -> useProxy)
      proxy_destroy (& fx -> proxy);
    enet_host_destroy (fx -> client.host);
    enet_host_destroy (fx -> server.host);
}

static void
fixture_pump (Fixture * fx, int milliseconds)
{
    enet_uint32 start = enet_time_get ();

    while ((enet_uint32) (enet_time_get () - start) < (enet_uint32) milliseconds)
    {
        side_service (& fx -> client, 1);
        side_service (& fx -> server, 1);
        if (fx -> useProxy)
          proxy_pump (& fx -> proxy);
    }
}

static int
fixture_wait_for (Fixture * fx, int (* condition) (Fixture *), int timeoutMs)
{
    enet_uint32 start = enet_time_get ();

    while ((enet_uint32) (enet_time_get () - start) < (enet_uint32) timeoutMs)
    {
        side_service (& fx -> client, 1);
        side_service (& fx -> server, 1);
        if (fx -> useProxy)
          proxy_pump (& fx -> proxy);
        if (condition (fx))
          return 1;
    }
    return 0;
}

static int
cond_both_connected (Fixture * fx)
{
    return fx -> client.connected && fx -> server.connected;
}

static ENetPeer *
fixture_connect (Fixture * fx, size_t channels, enet_uint32 data)
{
    fx -> client.peer = enet_host_connect (fx -> client.host, & fx -> connectAddress, channels, data);
    return fx -> client.peer;
}

/* fills a message with a deterministic pattern and accounts its bytes */
static ENetPacket *
make_message (enet_uint8 seed, size_t length, enet_uint32 flags, enet_uint64 * xorSum)
{
    ENetPacket * packet = enet_packet_create (NULL, length, flags);
    size_t i;

    for (i = 0; i < length; ++ i)
    {
        enet_uint8 byte = (enet_uint8) (seed + i * 13);
        packet -> data [i] = byte;
        * xorSum ^= byte;
    }
    return packet;
}

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

/* handshake + multi-channel echo + wire overhead check */
static void
test_handshake_echo (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;
    int i, saw136 = 0;

    printf ("test: handshake + multi-channel echo\n");

    if (fixture_init (& fx, 1, 1, 1, 4) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    fixture_connect (& fx, 4, 1234);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));
    CHECK (fx.server.connectData == 1234);
    CHECK (enet_peer_crypto_established (fx.client.peer));
    CHECK (enet_peer_crypto_established (fx.server.peer));
    CHECK (fx.client.host -> cryptoStats.handshakesCompleted == 1);
    CHECK (fx.server.host -> cryptoStats.handshakesCompleted == 1);

    /* reliable on channel 0, sent alone so its wire size is observable:
       4 (header+sentTime) + 10 (crypto hdr) + 6 (command) + 100 + 16 (tag) */
    packet = make_message (1, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);
    fixture_pump (& fx, 300);
    CHECK (fx.server.received == 1);

    for (i = 0; i < fx.proxy.clientPacketCount; ++ i)
      if (fx.proxy.clientPacketLengths [i] == 136)
        saw136 = 1;
    CHECK (saw136);

    /* unreliable on channel 1 */
    packet = make_message (2, 50, 0, & expectedXor);
    enet_peer_send (fx.client.peer, 1, packet);
    /* large reliable (fragmented) on channel 2 */
    packet = make_message (3, 4000, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 2, packet);
    /* unsequenced on channel 3 */
    packet = make_message (4, 64, ENET_PACKET_FLAG_UNSEQUENCED, & expectedXor);
    enet_peer_send (fx.client.peer, 3, packet);

    fixture_pump (& fx, 3000);

    CHECK (fx.server.received == 4);
    CHECK (fx.server.xorSum == expectedXor);
    CHECK (fx.server.channelCount [0] == 1);
    CHECK (fx.server.channelCount [1] == 1);
    CHECK (fx.server.channelCount [2] == 1);
    CHECK (fx.server.channelCount [3] == 1);
    CHECK (fx.server.host -> cryptoStats.packetsDecrypted > 0);
    CHECK (fx.server.host -> cryptoStats.droppedBadTag == 0);
    CHECK (fx.server.host -> cryptoStats.droppedReplay == 0);
    CHECK (fx.client.host -> cryptoStats.packetsEncrypted > 0);

    fixture_destroy (& fx);
}

/* default off: wire format and behavior must be unchanged */
static void
test_default_off (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;
    int i, saw52 = 0, saw110 = 0, sawCryptoSize = 0;

    printf ("test: default off regression\n");

    if (fixture_init (& fx, 0, 0, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    CHECK (! fx.client.host -> cryptoEnabled);
    CHECK (! fx.server.host -> cryptoEnabled);

    fixture_connect (& fx, 2, 7);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));
    CHECK (fx.server.connectData == 7);

    packet = make_message (9, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);

    fixture_pump (& fx, 2000);

    CHECK (fx.server.received == 1);
    CHECK (fx.server.xorSum == expectedXor);

    /* first client packet must be a bare CONNECT: 4 (header) + 48 = 52,
       and the 100-byte reliable message must be 4 + 6 + 100 = 110 with
       no crypto overhead anywhere */
    for (i = 0; i < fx.proxy.clientPacketCount; ++ i)
    {
        if (fx.proxy.clientPacketLengths [i] == 52)
          saw52 = 1;
        if (fx.proxy.clientPacketLengths [i] == 110)
          saw110 = 1;
        if (fx.proxy.clientPacketLengths [i] == 136 || fx.proxy.clientPacketLengths [i] == 140)
          sawCryptoSize = 1;
    }
    CHECK (saw52);
    CHECK (saw110);
    CHECK (! sawCryptoSize);

    fixture_destroy (& fx);
}

/* tamper with a ciphertext byte: drop + count, connection survives */
static int tamperArmed;
static int
hook_tamper (Proxy * proxy, enet_uint8 * data, int length, int fromClient)
{
    (void) proxy;
    if (fromClient && tamperArmed && length >= 100)
    {
        data [length - 3] ^= 0x40;   /* flip a bit inside the AEAD tag */
        tamperArmed = 0;
    }
    return PROXY_FORWARD;
}

static void
test_tamper (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;

    printf ("test: tampered packet dropped, connection survives\n");

    if (fixture_init (& fx, 1, 1, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }
    fx.proxy.onPacket = hook_tamper;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    tamperArmed = 1;
    packet = make_message (5, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);

    fixture_pump (& fx, 4000);

    /* tampered copy dropped; reliable retransmission still delivers */
    CHECK (fx.server.host -> cryptoStats.droppedBadTag >= 1);
    CHECK (fx.server.received == 1);
    CHECK (fx.server.xorSum == expectedXor);
    CHECK (! fx.client.disconnected && ! fx.server.disconnected);

    fixture_destroy (& fx);
}

/* replay a captured packet: dropped by the replay window */
static int replayArmed;
static int
hook_replay (Proxy * proxy, enet_uint8 * data, int length, int fromClient)
{
    (void) proxy;
    (void) data;
    if (fromClient && replayArmed && length >= 100)
    {
        replayArmed = 0;
        return PROXY_DUPLICATE;
    }
    return PROXY_FORWARD;
}

static void
test_replay (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;

    printf ("test: replayed packet dropped\n");

    if (fixture_init (& fx, 1, 1, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }
    fx.proxy.onPacket = hook_replay;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    replayArmed = 1;
    packet = make_message (6, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);

    fixture_pump (& fx, 2000);

    CHECK (fx.server.host -> cryptoStats.droppedReplay >= 1);
    CHECK (fx.server.received == 1);   /* delivered exactly once */
    CHECK (fx.server.xorSum == expectedXor);

    fixture_destroy (& fx);
}

/* truncate a packet: dropped, connection survives */
static int truncateArmed;
static int
hook_truncate (Proxy * proxy, enet_uint8 * data, int length, int fromClient)
{
    (void) proxy;
    (void) data;
    if (fromClient && truncateArmed && length >= 100)
    {
        truncateArmed = 0;
        /* forward only part of the datagram */
        proxy_send_to (proxy, & proxy -> serverAddress, data, length - 10);
        return PROXY_DROP;
    }
    return PROXY_FORWARD;
}

static void
test_truncation (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;

    printf ("test: truncated packet dropped, connection survives\n");

    if (fixture_init (& fx, 1, 1, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }
    fx.proxy.onPacket = hook_truncate;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    truncateArmed = 1;
    packet = make_message (7, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);

    fixture_pump (& fx, 4000);

    CHECK (fx.server.host -> cryptoStats.droppedTooShort +
           fx.server.host -> cryptoStats.droppedBadTag >= 1);
    CHECK (fx.server.received == 1);
    CHECK (fx.server.xorSum == expectedXor);
    CHECK (! fx.client.disconnected && ! fx.server.disconnected);

    fixture_destroy (& fx);
}

/* wrong pre-shared key: handshake never completes, failures counted */
static void
test_wrong_key (void)
{
    Fixture fx;
    ENetCryptoConfig config;

    printf ("test: wrong key rejected\n");

    if (fixture_init (& fx, 1, 1, 0, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    /* replace the client key with the wrong one */
    config.psk = PSK_B;
    config.pskLength = ENET_CRYPTO_KEY_SIZE;
    CHECK (enet_host_crypto_set (fx.client.host, & config) == 0);

    fixture_connect (& fx, 2, 0);
    enet_peer_timeout (fx.client.peer, 4, 400, 800);

    fixture_pump (& fx, 4000);

    CHECK (! fx.client.connected);
    CHECK (! fx.server.connected);
    CHECK (fx.server.host -> cryptoStats.handshakeFailures >= 1);
    CHECK (fx.client.disconnected);   /* connect attempt timed out */

    fixture_destroy (& fx);
}

/* downgrade: crypto client must not complete with a plaintext server */
static void
test_downgrade_plain_server (void)
{
    Fixture fx;

    printf ("test: crypto client refuses plaintext server\n");

    if (fixture_init (& fx, 1, 0, 0, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    fixture_connect (& fx, 2, 0);
    enet_peer_timeout (fx.client.peer, 4, 400, 800);

    fixture_pump (& fx, 4000);

    CHECK (! fx.client.connected);
    CHECK (fx.client.disconnected);

    fixture_destroy (& fx);
}

/* downgrade: crypto server must not complete with a plaintext client */
static void
test_downgrade_plain_client (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;

    printf ("test: crypto server refuses plaintext client\n");

    if (fixture_init (& fx, 0, 1, 0, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    fixture_connect (& fx, 2, 0);
    enet_peer_timeout (fx.client.peer, 4, 400, 800);

    /* the plaintext client completes its side of the vanilla handshake... */
    fixture_pump (& fx, 1500);
    CHECK (fx.client.connected);
    /* ...but the crypto server must not */
    CHECK (! fx.server.connected);

    /* plaintext data from the client is dropped and counted */
    packet = make_message (8, 100, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);

    fixture_pump (& fx, 2500);

    CHECK (! fx.server.connected);
    CHECK (fx.server.received == 0);
    CHECK (fx.server.host -> cryptoStats.droppedPlaintext >= 1);
    CHECK (fx.client.disconnected);   /* client times out: no acks ever come */

    fixture_destroy (& fx);
}

/* MITM replaces the handshake nonce: rejected, counted, and the
   legitimate handshake still completes afterwards */
static int mitmArmed;
static int
hook_mitm (Proxy * proxy, enet_uint8 * data, int length, int fromClient)
{
    (void) proxy;
    if (fromClient && mitmArmed && length > 4 + 48 + 8)
    {
        int headerSize = (data [0] & 0x80) ? 4 : 2;   /* sentTime flag */
        int cmd0 = data [headerSize] & 0x0F;
        int cmd1offset = headerSize + 48;             /* sizeof(ENetProtocolConnect) */
        int cmd1 = data [cmd1offset] & 0x0F;

        if (cmd0 == ENET_PROTOCOL_COMMAND_CONNECT &&
            cmd1 == ENET_PROTOCOL_COMMAND_CRYPTO_HANDSHAKE &&
            cmd1offset + 12 < length)
        {
            /* replace a byte of the client nonce (attacker has no PSK) */
            data [cmd1offset + 8] ^= 0xFF;
            mitmArmed = 0;
        }
    }
    return PROXY_FORWARD;
}

static void
test_mitm_handshake (void)
{
    Fixture fx;

    printf ("test: MITM handshake replacement rejected\n");

    if (fixture_init (& fx, 1, 1, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }
    fx.proxy.onPacket = hook_mitm;
    mitmArmed = 1;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    /* the forged INIT was rejected and counted; the retransmitted genuine
       INIT still completed the handshake */
    CHECK (fx.server.host -> cryptoStats.handshakeFailures >= 1);
    CHECK (enet_peer_crypto_established (fx.client.peer));
    CHECK (enet_peer_crypto_established (fx.server.peer));

    fixture_destroy (& fx);
}

/* key rotation, including an old-epoch straggler packet */
static int holdArmed;
static int
hook_hold (Proxy * proxy, enet_uint8 * data, int length, int fromClient)
{
    (void) proxy;
    (void) data;
    if (fromClient && holdArmed && length >= 100)
    {
        holdArmed = 0;
        return PROXY_HOLD;
    }
    return PROXY_FORWARD;
}

static void
test_rekey (void)
{
    Fixture fx;
    enet_uint64 xorToServer = 0, xorToClient = 0;
    ENetPacket * packet;

    printf ("test: key rotation\n");

    if (fixture_init (& fx, 1, 1, 1, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }
    fx.proxy.onPacket = hook_hold;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    /* hold one pre-rotation packet back (unreliable: no retransmission,
       so it can only arrive via the proxy) */
    {
        enet_uint64 heldXor = 0;   /* held message is never delivered */
        holdArmed = 1;
        packet = make_message (10, 100, 0, & heldXor);
        enet_peer_send (fx.client.peer, 0, packet);
    }
    fixture_pump (& fx, 200);
    CHECK (fx.proxy.haveHeld);
    CHECK (fx.server.received == 0);

    /* rotate client -> server, then send in the new epoch */
    CHECK (enet_peer_crypto_rekey (fx.client.peer) == 0);
    packet = make_message (11, 100, ENET_PACKET_FLAG_RELIABLE, & xorToServer);
    enet_peer_send (fx.client.peer, 0, packet);
    fixture_pump (& fx, 500);
    CHECK (fx.server.received == 1);
    CHECK (fx.server.peer -> crypto.recvEpoch == 1);

    /* rotate server -> client as well */
    CHECK (enet_peer_crypto_rekey (fx.server.peer) == 0);
    packet = make_message (12, 100, ENET_PACKET_FLAG_RELIABLE, & xorToClient);
    enet_peer_send (fx.server.peer, 0, packet);
    fixture_pump (& fx, 500);
    CHECK (fx.client.received == 1);
    CHECK (fx.client.peer -> crypto.recvEpoch == 1);

    /* now release the held pre-rotation packet: the crypto layer must
       still accept it (previous epoch key), even though ENet's own
       unreliable-sequencing may then discard the late command — exactly
       as it would for any grossly delayed vanilla packet */
    {
        ENetCryptoStats before = fx.server.host -> cryptoStats;

        proxy_inject_held (& fx.proxy);
        fixture_pump (& fx, 500);

        /* the injected packet reached the crypto layer and was accepted:
           decrypted counter advanced, no failure counter did */
        CHECK (fx.server.host -> cryptoStats.packetsDecrypted > before.packetsDecrypted);
        CHECK (fx.server.host -> cryptoStats.droppedBadTag == before.droppedBadTag);
        CHECK (fx.server.host -> cryptoStats.droppedBadEpoch == before.droppedBadEpoch);
        CHECK (fx.server.host -> cryptoStats.droppedReplay == before.droppedReplay);
        CHECK (fx.server.host -> cryptoStats.droppedTooShort == before.droppedTooShort);
    }

    CHECK (fx.server.received == 1);   /* msg 11 only; msg 10 was late */
    CHECK (fx.server.xorSum == xorToServer);
    CHECK (fx.client.received == 1);
    CHECK (fx.client.xorSum == xorToClient);
    CHECK (fx.server.host -> cryptoStats.droppedBadTag == 0);
    CHECK (fx.server.host -> cryptoStats.droppedBadEpoch == 0);
    CHECK (fx.server.host -> cryptoStats.droppedReplay == 0);
    CHECK (fx.client.host -> cryptoStats.rekeys == 1);
    CHECK (fx.server.host -> cryptoStats.rekeys == 1);

    fixture_destroy (& fx);
}

/* disconnect and reconnect: a fresh handshake produces fresh keys */
static void
test_reconnect (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;

    printf ("test: reconnect with fresh keys\n");

    if (fixture_init (& fx, 1, 1, 0, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));

    packet = make_message (13, 32, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);
    fixture_pump (& fx, 500);
    CHECK (fx.server.received == 1);

    enet_peer_disconnect (fx.client.peer, 0);
    fixture_pump (& fx, 2000);
    CHECK (fx.client.disconnected);
    CHECK (fx.server.disconnected);

    /* reconnect: new handshake, new nonces, new keys */
    fx.client.connected = fx.client.disconnected = 0;
    fx.server.connected = fx.server.disconnected = 0;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));
    CHECK (enet_peer_crypto_established (fx.client.peer));
    CHECK (enet_peer_crypto_established (fx.server.peer));
    CHECK (fx.client.host -> cryptoStats.handshakesCompleted == 2);
    CHECK (fx.server.host -> cryptoStats.handshakesCompleted == 2);

    packet = make_message (14, 32, ENET_PACKET_FLAG_RELIABLE, & expectedXor);
    enet_peer_send (fx.client.peer, 0, packet);
    fixture_pump (& fx, 1000);
    CHECK (fx.server.received == 2);
    CHECK (fx.server.xorSum == expectedXor);

    fixture_destroy (& fx);
}

/* crypto combined with the range-coder compressor and a checksum callback:
   compression must run before sealing, decompression after opening, and
   the checksum must only apply to plaintext (handshake) packets */
static void
test_compress_checksum (void)
{
    Fixture fx;
    enet_uint64 expectedXor = 0;
    ENetPacket * packet;
    int i;

    printf ("test: crypto + compressor + checksum\n");

    if (fixture_init (& fx, 1, 1, 0, 2) != 0)
    {
        printf ("  FAIL: fixture init\n");
        ++ failures;
        return;
    }

    enet_host_compress_with_range_coder (fx.client.host);
    enet_host_compress_with_range_coder (fx.server.host);
    fx.client.host -> checksum = enet_crc32;
    fx.server.host -> checksum = enet_crc32;

    fixture_connect (& fx, 2, 0);
    CHECK (fixture_wait_for (& fx, cond_both_connected, 5000));
    CHECK (enet_peer_crypto_established (fx.client.peer));
    CHECK (enet_peer_crypto_established (fx.server.peer));

    /* highly compressible payload */
    for (i = 0; i < 4; ++ i)
    {
        packet = enet_packet_create (NULL, 512, ENET_PACKET_FLAG_RELIABLE);
        memset (packet -> data, 'A' + i, 512);
        {
            int j;
            for (j = 0; j < 512; ++ j)
              expectedXor ^= (enet_uint8) ('A' + i);
        }
        enet_peer_send (fx.client.peer, 0, packet);
    }

    fixture_pump (& fx, 3000);

    CHECK (fx.server.received == 4);
    CHECK (fx.server.xorSum == expectedXor);
    CHECK (fx.server.host -> cryptoStats.droppedBadTag == 0);
    CHECK (fx.server.host -> cryptoStats.packetsDecrypted > 0);

    fixture_destroy (& fx);
}

int
main (void)
{
    if (enet_initialize () != 0)
    {
        printf ("enet_initialize failed\n");
        return 1;
    }

    test_handshake_echo ();
    test_default_off ();
    test_tamper ();
    test_replay ();
    test_truncation ();
    test_wrong_key ();
    test_downgrade_plain_server ();
    test_downgrade_plain_client ();
    test_mitm_handshake ();
    test_rekey ();
    test_reconnect ();
    test_compress_checksum ();

    enet_deinitialize ();

    if (failures > 0)
    {
        printf ("crypto integration: %d FAILURES\n", failures);
        return 1;
    }

    printf ("crypto integration: all tests passed\n");
    return 0;
}
