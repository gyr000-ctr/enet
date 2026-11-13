/**
 @file  migration.c
 @brief Reproducible two-host tests for optional connection migration.

 Simulates client address changes (NAT rebinding / network switch) by
 rebinding the client host socket to a new port on loopback, plus forged
 packets from raw sockets for the old-address, wrong-credential and
 challenge-failure paths.
*/
#include <stdio.h>
#include <string.h>
#include <enet/enet.h>
#include <enet/time.h>

static int failures = 0;
static int testCount = 0;

#define CHECK(cond) do { \
    if (! (cond)) { ++ failures; printf ("  FAIL %s:%d: %s\n", __FILE__, __LINE__, # cond); } \
  } while (0)

#define RUN_TEST(fn) do { \
    ++ testCount; \
    printf ("test %d: %s\n", testCount, # fn); \
    fn (); \
  } while (0)

typedef struct
{
    int          connectCount;
    int          disconnectCount;
    int          receiveCount;
    enet_uint32  received [64];
} EventLog;

static ENetAddress
make_address (enet_uint16 port)
{
    ENetAddress address;

    enet_address_set_host_ip (& address, "127.0.0.1");
    address.port = port;

    return address;
}

static ENetHost *
create_host (enet_uint16 port, int migration)
{
    ENetAddress address = make_address (port);
    ENetHost * host = enet_host_create (& address, 8, 2, 0, 0);

    if (host != NULL && migration)
      enet_host_enable_migration (host, 1);

    return host;
}

static void
service_host (ENetHost * host, EventLog * log, enet_uint32 timeout)
{
    ENetEvent event;

    while (enet_host_service (host, & event, timeout) > 0)
    {
        switch (event.type)
        {
        case ENET_EVENT_TYPE_CONNECT:
            ++ log -> connectCount;
            break;

        case ENET_EVENT_TYPE_DISCONNECT:
            ++ log -> disconnectCount;
            break;

        case ENET_EVENT_TYPE_RECEIVE:
            if (log -> receiveCount < 64 && event.packet -> dataLength >= sizeof (enet_uint32))
              memcpy (& log -> received [log -> receiveCount], event.packet -> data, sizeof (enet_uint32));
            ++ log -> receiveCount;
            enet_packet_destroy (event.packet);
            break;

        default:
            break;
        }

        timeout = 0;
    }
}

static void
pump (ENetHost * a, EventLog * la, ENetHost * b, EventLog * lb, enet_uint32 ms)
{
    enet_uint32 end = enet_time_get () + ms;

    do
    {
        service_host (a, la, 1);
        service_host (b, lb, 1);
    } while (enet_time_get () < end);
}

static void
pump_one (ENetHost * a, EventLog * la, enet_uint32 ms)
{
    enet_uint32 end = enet_time_get () + ms;

    do
      service_host (a, la, 1);
    while (enet_time_get () < end);
}

static ENetPeer *
connected_peer (ENetHost * host)
{
    ENetPeer * peer;

    for (peer = host -> peers; peer < & host -> peers [host -> peerCount]; ++ peer)
      if (peer -> state == ENET_PEER_STATE_CONNECTED)
        return peer;

    return NULL;
}

static int
connect_pair (ENetHost * server, ENetHost * client, enet_uint16 serverPort,
              EventLog * serverLog, EventLog * clientLog, ENetPeer ** clientPeer)
{
    ENetAddress address = make_address (serverPort);
    enet_uint32 end;

    * clientPeer = enet_host_connect (client, & address, 2, 0);
    if (* clientPeer == NULL)
      return -1;

    end = enet_time_get () + 3000;
    while ((serverLog -> connectCount == 0 || clientLog -> connectCount == 0) &&
           enet_time_get () < end)
    {
        service_host (server, serverLog, 1);
        service_host (client, clientLog, 1);
    }

    return serverLog -> connectCount == 1 && clientLog -> connectCount == 1 ? 0 : -1;
}

/* Simulates a NAT rebinding / network switch: the client keeps its ENet
   state but its datagrams now originate from a new address. */
static int
rebind_host (ENetHost * host, enet_uint16 port)
{
    ENetAddress address = make_address (port);

    enet_socket_destroy (host -> socket);

    host -> socket = enet_socket_create (ENET_SOCKET_TYPE_DATAGRAM);
    if (host -> socket == ENET_SOCKET_NULL)
      return -1;

    if (enet_socket_bind (host -> socket, & address) < 0)
      return -1;

    enet_socket_set_option (host -> socket, ENET_SOCKOPT_NONBLOCK, 1);
    enet_socket_set_option (host -> socket, ENET_SOCKOPT_BROADCAST, 1);

    return 0;
}

static void
send_counter (ENetPeer * peer, enet_uint32 value)
{
    ENetPacket * packet = enet_packet_create (& value, sizeof (value), ENET_PACKET_FLAG_RELIABLE);

    enet_peer_send (peer, 0, packet);
}

static ENetSocket
raw_socket (enet_uint16 port)
{
    ENetAddress address = make_address (port);
    ENetSocket sock = enet_socket_create (ENET_SOCKET_TYPE_DATAGRAM);

    if (sock == ENET_SOCKET_NULL)
      return ENET_SOCKET_NULL;

    if (enet_socket_bind (sock, & address) < 0)
    {
        enet_socket_destroy (sock);

        return ENET_SOCKET_NULL;
    }

    enet_socket_set_option (sock, ENET_SOCKOPT_NONBLOCK, 1);

    return sock;
}

/* The peerID/session bits the server expects in packets from its peer. */
static enet_uint16
peer_wire_id (const ENetPeer * serverPeer)
{
    return serverPeer -> incomingPeerID | (serverPeer -> incomingSessionID << ENET_PROTOCOL_HEADER_SESSION_SHIFT);
}

static void
raw_send (ENetSocket sock, enet_uint16 destPort, const void * data, size_t dataLength)
{
    ENetAddress address = make_address (destPort);
    ENetBuffer buffer;

    buffer.data = (void *) data;
    buffer.dataLength = dataLength;

    enet_socket_send (sock, & address, & buffer, 1);
}

static void
send_raw_migrate (ENetSocket sock, enet_uint16 destPort, enet_uint16 wireID,
                  enet_uint32 credential0, enet_uint32 credential1)
{
    enet_uint8 data [2 + sizeof (ENetProtocolMigrate)];
    ENetProtocolMigrate * command = (ENetProtocolMigrate *) (data + 2);
    enet_uint16 netID = ENET_HOST_TO_NET_16 (wireID);

    memcpy (data, & netID, 2);
    command -> header.command = ENET_PROTOCOL_COMMAND_MIGRATE;
    command -> header.channelID = 0xFF;
    command -> header.reliableSequenceNumber = 0;
    command -> credential [0] = ENET_HOST_TO_NET_32 (credential0);
    command -> credential [1] = ENET_HOST_TO_NET_32 (credential1);

    raw_send (sock, destPort, data, sizeof (data));
}

static void
send_raw_response (ENetSocket sock, enet_uint16 destPort, enet_uint16 wireID,
                   const enet_uint32 credential [2], const enet_uint32 token [2])
{
    enet_uint8 data [2 + sizeof (ENetProtocolMigrateResponse)];
    ENetProtocolMigrateResponse * command = (ENetProtocolMigrateResponse *) (data + 2);
    enet_uint16 netID = ENET_HOST_TO_NET_16 (wireID);

    memcpy (data, & netID, 2);
    command -> header.command = ENET_PROTOCOL_COMMAND_MIGRATE_RESPONSE;
    command -> header.channelID = 0xFF;
    command -> header.reliableSequenceNumber = 0;
    command -> credential [0] = ENET_HOST_TO_NET_32 (credential [0]);
    command -> credential [1] = ENET_HOST_TO_NET_32 (credential [1]);
    command -> token [0] = ENET_HOST_TO_NET_32 (token [0]);
    command -> token [1] = ENET_HOST_TO_NET_32 (token [1]);

    raw_send (sock, destPort, data, sizeof (data));
}

static void
send_raw_reliable (ENetSocket sock, enet_uint16 destPort, enet_uint16 wireID,
                   enet_uint16 reliableSequenceNumber, enet_uint32 payload)
{
    enet_uint8 data [2 + sizeof (ENetProtocolSendReliable) + sizeof (enet_uint32)];
    ENetProtocolSendReliable * command = (ENetProtocolSendReliable *) (data + 2);
    enet_uint16 netID = ENET_HOST_TO_NET_16 (wireID);

    memcpy (data, & netID, 2);
    command -> header.command = ENET_PROTOCOL_COMMAND_SEND_RELIABLE;
    command -> header.channelID = 0;
    command -> header.reliableSequenceNumber = ENET_HOST_TO_NET_16 (reliableSequenceNumber);
    command -> dataLength = ENET_HOST_TO_NET_16 (sizeof (payload));
    memcpy (data + 2 + sizeof (ENetProtocolSendReliable), & payload, sizeof (payload));

    raw_send (sock, destPort, data, sizeof (data));
}

static int
recv_raw_challenge (ENetSocket sock, enet_uint32 token [2])
{
    enet_uint8 data [256];
    ENetBuffer buffer;
    ENetAddress address;
    ENetProtocolMigrateChallenge * command;
    int receivedLength;

    buffer.data = data;
    buffer.dataLength = sizeof (data);

    receivedLength = enet_socket_receive (sock, & address, & buffer, 1);
    if (receivedLength < 2 + (int) sizeof (ENetProtocolMigrateChallenge))
      return 0;

    command = (ENetProtocolMigrateChallenge *) (data + 2);
    if ((command -> header.command & ENET_PROTOCOL_COMMAND_MASK) != ENET_PROTOCOL_COMMAND_MIGRATE_CHALLENGE)
      return 0;

    token [0] = ENET_NET_TO_HOST_32 (command -> token [0]);
    token [1] = ENET_NET_TO_HOST_32 (command -> token [1]);

    return 1;
}

static int
credential_is_zero (const enet_uint32 credential [2])
{
    return credential [0] == 0 && credential [1] == 0;
}

static int migrateInterceptCount = 0;

static int ENET_CALLBACK
count_migrate_intercept (ENetHost * host, ENetEvent * event)
{
    enet_uint16 peerID;
    size_t offset;

    if (host -> receivedDataLength < 3)
      return 0;

    memcpy (& peerID, host -> receivedData, 2);
    peerID = ENET_NET_TO_HOST_16 (peerID);
    offset = (peerID & ENET_PROTOCOL_HEADER_FLAG_SENT_TIME) ? sizeof (ENetProtocolHeader) : 2;

    if (host -> receivedDataLength < offset + 1)
      return 0;

    if ((host -> receivedData [offset] & ENET_PROTOCOL_COMMAND_MASK) == ENET_PROTOCOL_COMMAND_MIGRATE)
      ++ migrateInterceptCount;

    return 0;
}

/* Negotiation, address change, MIGRATE retransmission, challenge/response,
   and continuity of channels/sequence numbers/RTT across the switch. */
static void
test_negotiation_and_migration (void)
{
    ENetHost * server = create_host (15701, 1);
    ENetHost * client = create_host (15702, 1);
    EventLog serverLog = { 0 }, clientLog = { 0 };
    ENetPeer * clientPeer = NULL, * serverPeer;
    enet_uint32 rttBefore;
    int i;

    CHECK (server != NULL && client != NULL);
    CHECK (connect_pair (server, client, 15701, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL && clientPeer != NULL);
    if (serverPeer == NULL || clientPeer == NULL)
      return;

    /* per-connection credentials negotiated on top of the handshake */
    CHECK (! credential_is_zero (clientPeer -> incomingMigrateCredential));
    CHECK (! credential_is_zero (clientPeer -> outgoingMigrateCredential));
    CHECK (! credential_is_zero (serverPeer -> incomingMigrateCredential));
    CHECK (! credential_is_zero (serverPeer -> outgoingMigrateCredential));
    CHECK (clientPeer -> outgoingMigrateCredential [0] == serverPeer -> incomingMigrateCredential [0] &&
           clientPeer -> outgoingMigrateCredential [1] == serverPeer -> incomingMigrateCredential [1]);
    CHECK (clientPeer -> incomingMigrateCredential [0] == serverPeer -> outgoingMigrateCredential [0] &&
           clientPeer -> incomingMigrateCredential [1] == serverPeer -> outgoingMigrateCredential [1]);

    for (i = 0; i < 3; ++ i)
      send_counter (clientPeer, i + 1);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverLog.receiveCount == 3);
    CHECK (serverLog.received [0] == 1 && serverLog.received [1] == 2 && serverLog.received [2] == 3);

    rttBefore = serverPeer -> roundTripTime;

    /* a large (fragmented) reliable packet is sent but not yet acknowledged
       when the address changes; it must survive the switch */
    {
        enet_uint8 payload [3000];
        enet_uint32 marker = 100;
        ENetPacket * packet;

        memset (payload, 0x5A, sizeof (payload));
        memcpy (payload, & marker, sizeof (marker));
        packet = enet_packet_create (payload, sizeof (payload), ENET_PACKET_FLAG_RELIABLE);
        CHECK (enet_peer_send (clientPeer, 0, packet) == 0);
        pump_one (client, & clientLog, 50);
    }

    /* client address changes (NAT rebinding / network switch) */
    CHECK (rebind_host (client, 15703) == 0);
    CHECK (enet_peer_migrate (clientPeer) == 0);

    /* the client retransmits MIGRATE until the new path is confirmed */
    migrateInterceptCount = 0;
    server -> intercept = count_migrate_intercept;
    pump_one (client, & clientLog, 600);
    pump_one (server, & serverLog, 100);
    CHECK (migrateInterceptCount >= 2);

    pump (server, & serverLog, client, & clientLog, 1500);
    server -> intercept = NULL;

    /* the server switched the peer address only after the challenge succeeded */
    CHECK (serverPeer -> address.port == 15703);
    CHECK (clientPeer -> migrateState == ENET_PEER_MIGRATE_STATE_NONE);
    CHECK (serverLog.disconnectCount == 0 && clientLog.disconnectCount == 0);
    CHECK (serverLog.connectCount == 1 && clientLog.connectCount == 1);

    /* traffic resumes on both directions, in order, on the same channels */
    for (i = 0; i < 3; ++ i)
      send_counter (clientPeer, i + 4);
    for (i = 0; i < 3; ++ i)
      send_counter (serverPeer, i + 11);
    pump (server, & serverLog, client, & clientLog, 500);

    CHECK (serverLog.receiveCount == 7);
    CHECK (serverLog.received [3] == 100);
    CHECK (serverLog.received [4] == 4 && serverLog.received [5] == 5 && serverLog.received [6] == 6);
    CHECK (clientLog.receiveCount == 3);
    CHECK (clientLog.received [0] == 11 && clientLog.received [1] == 12 && clientLog.received [2] == 13);

    /* sequence numbers and RTT statistics were preserved, not reset
       (3 small + 3 fragments of the large packet + 3 small = seq 9) */
    CHECK (serverPeer -> channels [0].incomingReliableSequenceNumber == 9);
    CHECK (clientPeer -> channels [0].incomingReliableSequenceNumber == 3);
    CHECK (serverPeer -> roundTripTime <= rttBefore + 10);
    CHECK (serverPeer -> roundTripTime < ENET_PEER_DEFAULT_ROUND_TRIP_TIME || rttBefore == ENET_PEER_DEFAULT_ROUND_TRIP_TIME);

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* After migration, packets from the old address (including ones with a valid
   session and next-in-line sequence numbers) must be dropped, and a MIGRATE
   with a wrong credential must not move the connection. */
static void
test_old_address_and_wrong_credential (void)
{
    ENetHost * server = create_host (15711, 1);
    ENetHost * client = create_host (15712, 1);
    EventLog serverLog = { 0 }, clientLog = { 0 };
    ENetPeer * clientPeer = NULL, * serverPeer;
    ENetSocket raw;
    enet_uint32 token [2];
    int receiveBase;

    CHECK (connect_pair (server, client, 15711, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL && clientPeer != NULL);
    if (serverPeer == NULL || clientPeer == NULL)
      return;

    send_counter (clientPeer, 1);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverLog.receiveCount == 1);

    CHECK (rebind_host (client, 15713) == 0);
    CHECK (enet_peer_migrate (clientPeer) == 0);
    pump (server, & serverLog, client, & clientLog, 1500);
    CHECK (serverPeer -> address.port == 15713);

    /* a third party now controls the old address */
    raw = raw_socket (15712);
    CHECK (raw != ENET_SOCKET_NULL);

    receiveBase = serverLog.receiveCount;

    /* forged data packet from the old address with valid session and the
       sequence number that would be accepted from the real peer */
    send_raw_reliable (raw, 15711, peer_wire_id (serverPeer),
                       serverPeer -> channels [0].incomingReliableSequenceNumber + 1,
                       0xDEADBEEF);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverLog.receiveCount == receiveBase);
    CHECK (serverPeer -> address.port == 15713);

    /* forged MIGRATE with a wrong credential: no challenge, no switch */
    send_raw_migrate (raw, 15711, peer_wire_id (serverPeer), 0xBAD0BAD0, 0xBAD1BAD1);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverPeer -> address.port == 15713);
    CHECK (recv_raw_challenge (raw, token) == 0);
    CHECK (serverPeer -> migrateChallengeTime == 0);

    /* the original connection is still usable */
    send_counter (clientPeer, 2);
    send_counter (serverPeer, 3);
    pump (server, & serverLog, client, & clientLog, 500);
    CHECK (serverLog.receiveCount == receiveBase + 1);
    CHECK (serverLog.received [receiveBase] == 2);
    CHECK (clientLog.received [clientLog.receiveCount - 1] == 3);
    CHECK (serverLog.disconnectCount == 0 && clientLog.disconnectCount == 0);

    enet_socket_destroy (raw);
    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* A third party at a fresh address without the credential gets no challenge
   and cannot preempt the address of the connection. */
static void
test_third_party_preemption_fails (void)
{
    ENetHost * server = create_host (15721, 1);
    ENetHost * client = create_host (15722, 1);
    EventLog serverLog = { 0 }, clientLog = { 0 };
    ENetPeer * clientPeer = NULL, * serverPeer;
    ENetSocket raw;
    enet_uint32 token [2];

    CHECK (connect_pair (server, client, 15721, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL);
    if (serverPeer == NULL)
      return;

    raw = raw_socket (15723);
    CHECK (raw != ENET_SOCKET_NULL);

    send_raw_migrate (raw, 15721, peer_wire_id (serverPeer), 0x12345678, 0x9ABCDEF0);
    pump (server, & serverLog, client, & clientLog, 400);

    CHECK (serverPeer -> address.port == 15722);
    CHECK (serverPeer -> migrateChallengeTime == 0);
    CHECK (recv_raw_challenge (raw, token) == 0);

    send_counter (clientPeer, 7);
    pump (server, & serverLog, client, & clientLog, 400);
    CHECK (serverLog.receiveCount == 1 && serverLog.received [0] == 7);
    CHECK (serverLog.disconnectCount == 0 && clientLog.disconnectCount == 0);

    enet_socket_destroy (raw);
    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* A valid credential alone is not enough: wrong challenge tokens and expired
   challenges are rejected and the connection stays on the old address. */
static void
test_challenge_token_and_timeout (void)
{
    ENetHost * server = create_host (15731, 1);
    ENetHost * client = create_host (15732, 1);
    EventLog serverLog = { 0 }, clientLog = { 0 };
    ENetPeer * clientPeer = NULL, * serverPeer;
    ENetSocket raw;
    enet_uint32 token [2] = { 0, 0 }, badToken [2];

    CHECK (connect_pair (server, client, 15731, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL);
    if (serverPeer == NULL)
      return;

    raw = raw_socket (15733);
    CHECK (raw != ENET_SOCKET_NULL);

    /* a MIGRATE with the correct credential does elicit a path challenge */
    send_raw_migrate (raw, 15731, peer_wire_id (serverPeer),
                      serverPeer -> incomingMigrateCredential [0],
                      serverPeer -> incomingMigrateCredential [1]);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (recv_raw_challenge (raw, token) == 1);
    CHECK (token [0] != 0 || token [1] != 0);
    CHECK (serverPeer -> address.port == 15732);

    /* wrong token: rejected */
    badToken [0] = token [0] ^ 0xFFFFFFFFU;
    badToken [1] = token [1];
    send_raw_response (raw, 15731, peer_wire_id (serverPeer),
                       serverPeer -> incomingMigrateCredential, badToken);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverPeer -> address.port == 15732);

    /* expired challenge: rejected even with the correct token */
    serverPeer -> migrateChallengeTime = server -> serviceTime - (ENET_PEER_MIGRATE_CHALLENGE_TIMEOUT + 1000);
    send_raw_response (raw, 15731, peer_wire_id (serverPeer),
                       serverPeer -> incomingMigrateCredential, token);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverPeer -> address.port == 15732);
    CHECK (serverPeer -> migrateChallengeTime == 0);

    /* the original connection is still usable */
    send_counter (clientPeer, 9);
    pump (server, & serverLog, client, & clientLog, 400);
    CHECK (serverLog.receiveCount == 1 && serverLog.received [0] == 9);
    CHECK (serverLog.disconnectCount == 0 && clientLog.disconnectCount == 0);

    enet_socket_destroy (raw);
    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Default behaviour is unchanged: strict address binding, no credential
   negotiation, packets from a new address are dropped. */
static void
test_disabled_by_default (void)
{
    ENetHost * server = create_host (15741, 0);
    ENetHost * client = create_host (15742, 0);
    EventLog serverLog = { 0 }, clientLog = { 0 };
    ENetPeer * clientPeer = NULL, * serverPeer;

    CHECK (server -> enableMigration == 0 && client -> enableMigration == 0);
    CHECK (connect_pair (server, client, 15741, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL && clientPeer != NULL);
    if (serverPeer == NULL || clientPeer == NULL)
      return;

    CHECK (credential_is_zero (clientPeer -> incomingMigrateCredential));
    CHECK (credential_is_zero (clientPeer -> outgoingMigrateCredential));
    CHECK (credential_is_zero (serverPeer -> incomingMigrateCredential));
    CHECK (credential_is_zero (serverPeer -> outgoingMigrateCredential));

    send_counter (clientPeer, 1);
    pump (server, & serverLog, client, & clientLog, 300);
    CHECK (serverLog.receiveCount == 1);

    CHECK (rebind_host (client, 15743) == 0);
    CHECK (enet_peer_migrate (clientPeer) == -1);

    pump (server, & serverLog, client, & clientLog, 800);

    /* nothing from the new address is accepted; the binding is unchanged */
    CHECK (serverLog.receiveCount == 1);
    CHECK (serverPeer -> address.port == 15742);
    CHECK (serverPeer -> state == ENET_PEER_STATE_CONNECTED);
    CHECK (clientPeer -> state == ENET_PEER_STATE_CONNECTED);
    CHECK (serverLog.disconnectCount == 0 && clientLog.disconnectCount == 0);

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Migration must be negotiated by both ends: with only one side enabled the
   connection works normally but cannot migrate. */
static void
test_one_sided_enable (void)
{
    ENetHost * server, * client;
    EventLog serverLog, clientLog;
    ENetPeer * clientPeer, * serverPeer;

    /* server enabled, client not */
    server = create_host (15751, 1);
    client = create_host (15752, 0);
    memset (& serverLog, 0, sizeof (serverLog));
    memset (& clientLog, 0, sizeof (clientLog));
    clientPeer = NULL;

    CHECK (connect_pair (server, client, 15751, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL && clientPeer != NULL);
    if (serverPeer != NULL && clientPeer != NULL)
    {
        CHECK (credential_is_zero (serverPeer -> incomingMigrateCredential));
        CHECK (credential_is_zero (clientPeer -> outgoingMigrateCredential));
        CHECK (enet_peer_migrate (clientPeer) == -1);

        send_counter (clientPeer, 1);
        send_counter (serverPeer, 2);
        pump (server, & serverLog, client, & clientLog, 400);
        CHECK (serverLog.receiveCount == 1 && clientLog.receiveCount == 1);
    }
    enet_host_destroy (client);
    enet_host_destroy (server);

    /* client enabled, server not: the extended CONNECT is parsed fine by a
       peer that has migration disabled, but no credentials are established */
    server = create_host (15761, 0);
    client = create_host (15762, 1);
    memset (& serverLog, 0, sizeof (serverLog));
    memset (& clientLog, 0, sizeof (clientLog));
    clientPeer = NULL;

    CHECK (connect_pair (server, client, 15761, & serverLog, & clientLog, & clientPeer) == 0);
    serverPeer = connected_peer (server);
    CHECK (serverPeer != NULL && clientPeer != NULL);
    if (serverPeer != NULL && clientPeer != NULL)
    {
        CHECK (! credential_is_zero (clientPeer -> incomingMigrateCredential));
        CHECK (credential_is_zero (clientPeer -> outgoingMigrateCredential));
        CHECK (credential_is_zero (serverPeer -> incomingMigrateCredential));
        CHECK (enet_peer_migrate (clientPeer) == -1);

        send_counter (clientPeer, 1);
        send_counter (serverPeer, 2);
        pump (server, & serverLog, client, & clientLog, 400);
        CHECK (serverLog.receiveCount == 1 && clientLog.receiveCount == 1);
    }
    enet_host_destroy (client);
    enet_host_destroy (server);
}

int
main (void)
{
    if (enet_initialize () != 0)
    {
        fprintf (stderr, "enet_initialize failed\n");

        return 1;
    }

    RUN_TEST (test_negotiation_and_migration);
    RUN_TEST (test_old_address_and_wrong_credential);
    RUN_TEST (test_third_party_preemption_fails);
    RUN_TEST (test_challenge_token_and_timeout);
    RUN_TEST (test_disabled_by_default);
    RUN_TEST (test_one_sided_enable);

    enet_deinitialize ();

    printf ("%d tests, %d failure(s)\n", testCount, failures);

    return failures != 0;
}
