/*
 * test_mtu.c - simulated path MTU discovery tests for ENet.
 *
 * Two ENet hosts are run in one process over real loopback UDP sockets. A
 * host intercept callback emulates the IP path: it drops any datagram larger
 * than a configurable path MTU (simulating a tunnel/mobile link) and can enter
 * a black-hole mode in which all datagrams are dropped. No real IP
 * fragmentation occurs because the test never leaves the loopback interface;
 * the intercept layer enforces the emulated link constraint instead.
 *
 * Build: see CMakeLists.txt option ENET_BUILD_TESTS, or directly:
 *   cc -I../include test_mtu.c ../build/libenet.a -o test_mtu
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define ENET_BUILDING_LIB 1
#include "enet/enet.h"

/* Emulated path state shared by both hosts' intercept callbacks. */
static enet_uint32 g_path_mtu = 1500;
static int         g_blackhole = 0;
static int         g_intercept_enabled = 1;

/* Last real MTU probe seen on the wire, used to craft a forged ack. */
static enet_uint16 g_captured_peer_id = 0;
static int         g_captured_probe = 0;

static int
path_intercept (ENetHost * host, ENetEvent * event)
{
    (void) host;
    (void) event;

    if (! g_intercept_enabled)
      return 0;

    if (g_blackhole)
      return 1; /* swallow every datagram: emulated black hole */

    if (host -> receivedDataLength > g_path_mtu)
      return 1; /* emulated path MTU exceeded: datagram dropped */

    if (host -> receivedDataLength >= 2 + sizeof (ENetProtocolMtuProbe))
    {
        enet_uint8 command = host -> receivedData [2] & ENET_PROTOCOL_COMMAND_MASK;
        if (command == ENET_PROTOCOL_COMMAND_MTU_PROBE)
        {
            memcpy (& g_captured_peer_id, host -> receivedData, sizeof (enet_uint16));
            g_captured_probe = 1;
        }
    }

    return 0;
}

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, message) do { \
    ++ g_checks; \
    if (!(cond)) { ++ g_failures; printf ("  FAIL: %s\n", message); } \
    else         { printf ("  ok:   %s\n", message); } \
} while (0)

static ENetHost *
make_host (int is_server, size_t peer_count)
{
    ENetAddress addr;
    ENetHost * host;

    memset (& addr, 0, sizeof (addr));
    if (is_server)
    {
        addr.host = ENET_HOST_ANY;
        addr.port = 0; /* ephemeral port */
        host = enet_host_create (& addr, peer_count, 2, 0, 0);
    }
    else
      host = enet_host_create (NULL, peer_count, 2, 0, 0);

    if (host == NULL)
    {
        printf ("fatal: enet_host_create returned NULL\n");
        exit (2);
    }

    host -> intercept = path_intercept;
    return host;
}

static void
pump (ENetHost * a, ENetHost * b, enet_uint32 ms)
{
    enet_uint32 end = enet_time_get () + ms;
    ENetEvent event;

    /* Drive both protocol machines. While a peer has not dispatched its
     * connect notification yet, service with an event so it reaches CONNECTED
     * (which enet_peer_send requires); its connect event carries no packet.
     * Once connected, service with a NULL event so RECEIVE packets are never
     * drained/destroyed here and tests that assert on delivered data can read
     * them in their own service loop. */
    while (enet_time_get () < end)
    {
        if (a -> connectedPeers == 0)
          while (enet_host_service (a, & event, 0) > 0 && event.type == ENET_EVENT_TYPE_RECEIVE)
            enet_packet_destroy (event.packet);
        else
          enet_host_service (a, NULL, 1);

        if (b -> connectedPeers == 0)
          while (enet_host_service (b, & event, 0) > 0 && event.type == ENET_EVENT_TYPE_RECEIVE)
            enet_packet_destroy (event.packet);
        else
          enet_host_service (b, NULL, 1);
    }
}

static ENetPeer *
connect_pair (ENetHost * client, ENetHost * server)
{
    ENetAddress addr;
    ENetEvent event;
    ENetPeer * peer;
    enet_uint32 start;

    enet_address_set_host_ip (& addr, "127.0.0.1");
    addr.port = server -> address.port;

    peer = enet_host_connect (client, & addr, 2, 0);
    if (peer == NULL)
    {
        printf ("fatal: enet_host_connect returned NULL\n");
        exit (2);
    }

    start = enet_time_get ();
    while (enet_time_get () - start < 5000)
    {
        if (enet_host_service (client, & event, 50) > 0 &&
            event.type == ENET_EVENT_TYPE_CONNECT)
          break;
        enet_host_service (server, NULL, 1);
    }

    start = enet_time_get ();
    while (enet_time_get () - start < 1000)
    {
        if (enet_host_service (server, & event, 50) > 0 &&
            event.type == ENET_EVENT_TYPE_CONNECT)
          return peer;
        enet_host_service (client, NULL, 1);
    }

    printf ("fatal: handshake did not complete\n");
    exit (2);
}

static ENetPacket *
make_packet (size_t size, enet_uint32 flags)
{
    ENetPacket * packet = enet_packet_create (NULL, size, flags);
    if (packet == NULL)
    {
        printf ("fatal: packet alloc failed\n");
        exit (2);
    }
    memset (packet -> data, 0xAB, size);
    return packet;
}

static void
print_stats (const char * label, const ENetMtuStats * s)
{
    printf ("  stats[%s]: sent=%u acked=%u lost=%u acksSent=%u rejected=%u "
            "inc=%u dec=%u blackhole=%u reseg=%u lastProbe=%u\n",
            label, s -> probesSent, s -> probesAcked, s -> probesLost,
            s -> acksSent, s -> probesRejected, s -> mtuIncreases,
            s -> mtuDecreases, s -> blackHoleEvents, s -> resegmentations,
            s -> lastProbeMtu);
}

/* Test 1: with PMTUD disabled (default), behaviour is unchanged even when the
 * emulated path is far smaller than the fixed host MTU. */
static void
test_default_regression (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetPeer * peer;
    ENetMtuStats stats;
    ENetPacket * packet;

    printf ("\n[test] default fixed-MTU regression (PMTUD disabled)\n");

    g_path_mtu = 600; /* smaller than the 1392 default MTU */
    g_blackhole = 0;

    peer = connect_pair (client, server);

    CHECK (peer -> mtu == ENET_HOST_DEFAULT_MTU, "peer keeps fixed default MTU with PMTUD off");
    enet_peer_get_mtu_stats (peer, & stats);
    CHECK (stats.probesSent == 0, "no probes are sent when PMTUD is disabled");
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_DISABLED, "discovery state is DISABLED");
    CHECK (enet_peer_start_mtu_discovery (peer) < 0, "starting discovery while disabled fails");

    /* Small packets still fit the emulated path and deliver. */
    packet = make_packet (64, ENET_PACKET_FLAG_RELIABLE);
    CHECK (enet_peer_send (peer, 0, packet) == 0, "small reliable packet accepted");
    pump (client, server, 300);
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection stays usable on the small path");

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 2: a converged peer reacts to a shrinking path MTU, re-segments queued
 * packets, and recovers after the path grows back. */
static void
test_decrease_and_recovery (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    ENetMtuStats stats;
    ENetPacket * packet;
    enet_uint32 first_mtu;
    enet_uint32 start;

    printf ("\n[test] decreasing path MTU, re-segmentation and recovery\n");

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 3;
    config.blackHoleBackoff = 500;
    config.revalidateTime = 0;
    config.allowFragmentation = 1;
    CHECK (enet_host_enable_mtu_discovery (server, & config) == 0, "PMTUD enabled on server");
    CHECK (enet_host_enable_mtu_discovery (client, & config) == 0, "PMTUD enabled on client");

    g_path_mtu = 1400;
    g_blackhole = 0;

    peer = connect_pair (client, server);
    CHECK (peer -> mtu == ENET_PROTOCOL_MINIMUM_MTU, "peer begins at safe minimum MTU");

    /* Run until the client's search converges near the path MTU. */
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "search converged on large path");
    CHECK (peer -> mtu > ENET_PROTOCOL_MINIMUM_MTU, "MTU increased above the safe floor");
    CHECK (peer -> mtu <= g_path_mtu, "confirmed MTU never exceeds the path MTU");
    CHECK (stats.probesAcked > 0 && stats.probesSent >= stats.probesAcked, "probes were acked");
    first_mtu = peer -> mtu;

    /* A packet fragmented at the old, larger MTU is queued. Discovery is then
     * restarted before any service/flush so the fragments are still held in the
     * outgoing queues when the MTU collapses, forcing a re-segmentation. */
    packet = make_packet (2000, ENET_PACKET_FLAG_RELIABLE);
    CHECK (enet_peer_send (peer, 0, packet) == 0, "large reliable packet fragmented and queued");

    g_path_mtu = 700;
    CHECK (enet_peer_start_mtu_discovery (peer) == 0, "discovery restarted after path shrank");
    CHECK (peer -> mtu == ENET_PROTOCOL_MINIMUM_MTU, "restart drops back to the safe floor");
    CHECK (peer -> mtuDiscovery.resegmentPending == 1, "re-segmentation requested while fragments are queued");

    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "re-converged on the smaller path");
    CHECK (peer -> mtu <= g_path_mtu, "new MTU respects the shrunken path");
    CHECK (peer -> mtu < first_mtu, "MTU decreased relative to the first path");
    CHECK (stats.mtuDecreases > 0, "at least one MTU decrease was recorded");
    CHECK (stats.resegmentations > 0, "queued packets were re-segmented for the new MTU");
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection survived the MTU collapse");

    /* The re-segmented packet must still arrive intact at the server. Give the
     * reliable retransmits a generous window now that discovery has settled. */
    {
        ENetEvent ev;
        enet_uint32 got = 0;
        start = enet_time_get ();
        while (enet_time_get () - start < 5000 && got < 2000)
        {
            if (enet_host_service (server, & ev, 50) > 0 &&
                ev.type == ENET_EVENT_TYPE_RECEIVE)
            {
                got += (enet_uint32) ev.packet -> dataLength;
                enet_packet_destroy (ev.packet);
            }
            enet_host_service (client, NULL, 1);
        }
        CHECK (got == 2000, "re-segmented 2000-byte packet delivered completely");
    }

    /* Recovery: grow the path back and restart; the MTU must rise again. */
    g_path_mtu = 1400;
    CHECK (enet_peer_start_mtu_discovery (peer) == 0, "discovery restarted after path recovered");
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtu > 700, "MTU recovered upwards after the path grew");
    CHECK (stats.mtuIncreases > 0, "MTU increases were recorded");
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection still usable after recovery");

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 3: a total black hole drives probes (and reliable traffic) down to the
 * safe floor without disconnecting; clearing the black hole lets the search
 * recover. */
static void
test_black_hole (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    ENetMtuStats stats;
    enet_uint32 start;

    printf ("\n[test] black hole fallback and recovery\n");

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 2;
    config.blackHoleBackoff = 400;
    config.revalidateTime = 0;
    config.allowFragmentation = 1;
    enet_host_enable_mtu_discovery (server, & config);
    enet_host_enable_mtu_discovery (client, & config);

    g_path_mtu = 1400;
    g_blackhole = 0;

    peer = connect_pair (client, server);
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "converged before black hole");
    CHECK (peer -> mtu > ENET_PROTOCOL_MINIMUM_MTU, "had a non-trivial MTU before the black hole");

    /* Black hole: every datagram is dropped, including probes. */
    g_blackhole = 1;
    CHECK (enet_peer_start_mtu_discovery (peer) == 0, "restarted discovery inside the black hole");

    start = enet_time_get ();
    while (enet_time_get () - start < 3000 &&
           peer -> mtuDiscovery.stats.blackHoleEvents == 0)
      pump (client, server, 20);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (stats.blackHoleEvents > 0, "a black hole was detected");
    CHECK (peer -> mtu == ENET_PROTOCOL_MINIMUM_MTU, "fell back to the safe MTU in the black hole");
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_BLACK_HOLE, "entered BLACK_HOLE state");
    CHECK (stats.probesLost > 0, "lost probes were counted as diagnostics");

    /* Clear the black hole well inside the normal 30s peer timeout and confirm
     * the connection recovers and re-converges. */
    g_blackhole = 0;
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "re-converged after black hole cleared");
    CHECK (peer -> mtu > ENET_PROTOCOL_MINIMUM_MTU, "MTU climbed back above the floor");
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection stayed alive throughout");

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 4: with fragmentation disabled, packets that do not fit the current
 * confirmed MTU are rejected rather than fragmented; fitting packets work. */
static void
test_fragmentation_disabled (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    ENetPacket * packet;
    enet_uint32 start;

    printf ("\n[test] fragmentation disabled honors the current MTU\n");

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 3;
    config.blackHoleBackoff = 400;
    config.revalidateTime = 0;
    config.allowFragmentation = 0;
    enet_host_enable_mtu_discovery (server, & config);
    enet_host_enable_mtu_discovery (client, & config);

    g_path_mtu = 900;
    g_blackhole = 0;

    peer = connect_pair (client, server);
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "converged with fragmentation off");

    /* A packet exceeding the fragment payload at the confirmed MTU is refused;
     * the caller retains ownership and must destroy it. */
    packet = make_packet (peer -> mtu, ENET_PACKET_FLAG_RELIABLE);
    CHECK (enet_peer_send (peer, 0, packet) < 0, "oversized packet rejected instead of fragmented");
    enet_packet_destroy (packet);

    /* A packet that fits is accepted and delivered. */
    packet = make_packet (128, ENET_PACKET_FLAG_RELIABLE);
    CHECK (enet_peer_send (peer, 0, packet) == 0, "fitting packet accepted with fragmentation off");
    {
        ENetEvent ev;
        enet_uint32 got = 0;
        start = enet_time_get ();
        while (enet_time_get () - start < 2000 && got == 0)
        {
            if (enet_host_service (server, & ev, 50) > 0 &&
                ev.type == ENET_EVENT_TYPE_RECEIVE)
            {
                got = (enet_uint32) ev.packet -> dataLength;
                enet_packet_destroy (ev.packet);
            }
            enet_host_service (client, NULL, 1);
        }
        CHECK (got == 128, "fitting packet delivered with fragmentation off");
    }

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 5: periodic revalidation detects a shrinking path (MTU jitter) after
 * convergence and adapts without disconnecting, then holds the MTU while the
 * path is stable instead of flapping on every probe. */
static void
test_revalidation_jitter (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    ENetMtuStats stats;
    enet_uint32 start;
    enet_uint32 stable_mtu;

    printf ("\n[test] periodic revalidation handles MTU jitter\n");

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 2;
    config.blackHoleBackoff = 400;
    /* Short revalidation interval so the test does not have to wait long. */
    config.revalidateTime = 400;
    config.allowFragmentation = 1;
    enet_host_enable_mtu_discovery (server, & config);
    enet_host_enable_mtu_discovery (client, & config);

    g_path_mtu = 1400;
    g_blackhole = 0;

    peer = connect_pair (client, server);
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "converged on the large path");
    CHECK (peer -> mtu > ENET_PROTOCOL_MINIMUM_MTU, "non-trivial MTU before jitter");
    stable_mtu = peer -> mtu;

    /* While the path stays healthy, revalidation must not churn the MTU. */
    pump (client, server, 1200);
    CHECK (peer -> mtu == stable_mtu, "MTU stays stable during healthy revalidation");
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "still converged while stable");

    /* The path suddenly shrinks below the converged MTU. The next revalidation
     * probe is too large, fails, and discovery reopens underneath it. */
    g_path_mtu = 700;
    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           (peer -> mtu >= 700 || peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED))
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtu < stable_mtu, "MTU adapted downward after the path shrank");
    CHECK (peer -> mtu <= g_path_mtu, "adapted MTU respects the new path limit");
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "re-converged after jitter");
    CHECK (stats.mtuDecreases > 0, "jitter-induced decrease was recorded");
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection survived MTU jitter");

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 6: a forged acknowledgement that fails authentication must not move the
 * MTU and must be counted as a rejected probe. */
static void
test_forged_ack_rejected (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    enet_uint32 mtu_before;
    enet_uint8 datagram [ENET_PROTOCOL_MAXIMUM_MTU];
    ENetProtocolHeader * header = (ENetProtocolHeader *) datagram;
    ENetProtocolMtuAck * ack;
    ENetAddress target;
    enet_uint32 start;

    printf ("\n[test] forged probe acknowledgement is rejected\n");

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 3;
    config.blackHoleBackoff = 400;
    config.revalidateTime = 0;
    config.allowFragmentation = 1;
    enet_host_enable_mtu_discovery (server, & config);
    enet_host_enable_mtu_discovery (client, & config);

    g_path_mtu = 1400;
    g_blackhole = 0;
    g_captured_probe = 0;

    peer = connect_pair (client, server);

    /* Let discovery fully converge and settle on both hosts so the MTU is
     * stable and no legitimate probe is in flight when the forged packet lands. */
    start = enet_time_get ();
    while (enet_time_get () - start < 6000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);
    pump (client, server, 300);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "discovery converged before the forged packet");
    CHECK (g_captured_probe, "a genuine probe was observed on the path");

    /* The forged ack is addressed to the server, so the MTU that must be
     * protected from it is the server-side peer's. Record it while stable. */
    {
        ENetPeer * serverPeer = NULL;
        size_t i;
        for (i = 0; i < server -> peerCount; ++ i)
        {
            if (server -> peers [i].state == ENET_PEER_STATE_CONNECTED)
            {
                serverPeer = & server -> peers [i];
                break;
            }
        }
        CHECK (serverPeer != NULL, "connected server-side peer located");
        if (serverPeer != NULL)
          mtu_before = serverPeer -> mtu;
    }

    /* Forge an ack using a valid peer/session header but bogus cookie/nonce. */
    memset (datagram, 0, sizeof (datagram));
    header -> peerID = g_captured_peer_id; /* correct peer + session bits */
    ack = (ENetProtocolMtuAck *) (datagram + 2);
    ack -> header.command = ENET_PROTOCOL_COMMAND_MTU_ACK;
    ack -> header.channelID = 0xFF;
    ack -> cookie = ENET_HOST_TO_NET_32 (0xDEADBEEF);
    ack -> probeMtu = ENET_HOST_TO_NET_32 (1400);
    ack -> nonce = ENET_HOST_TO_NET_32 (0xCAFEBABE);

    target.host = server -> address.host;
    target.port = server -> address.port;
    {
        ENetBuffer buffer;
        buffer.data = datagram;
        buffer.dataLength = 2 + sizeof (ENetProtocolMtuAck);
        CHECK (enet_socket_send (client -> socket, & target, & buffer, 1) >= 0,
               "forged ack datagram injected");
    }

    pump (client, server, 300);

    /* The forged ack was sent to the server, so it is the server's peer that
     * must reject it. Find the server-side peer for this connection. */
    {
        ENetMtuStats after;
        ENetPeer * serverPeer = NULL;
        size_t i;

        for (i = 0; i < server -> peerCount; ++ i)
        {
            if (server -> peers [i].state != ENET_PEER_STATE_DISCONNECTED)
            {
                serverPeer = & server -> peers [i];
                break;
            }
        }

        CHECK (serverPeer != NULL, "server-side peer located");
        if (serverPeer != NULL)
        {
            enet_peer_get_mtu_stats (serverPeer, & after);
            print_stats ("server", & after);
            CHECK (after.probesRejected > 0, "forged ack counted as rejected on the receiver");
            CHECK (serverPeer -> mtu >= ENET_PROTOCOL_MINIMUM_MTU, "receiver peer still usable");
            /* The decisive security property: an unauthenticated ack must not
             * move the receiver's MTU away from its previously confirmed value. */
            CHECK (serverPeer -> mtu == mtu_before,
                   "receiver MTU unchanged by the forged acknowledgement");
        }
    }

    enet_host_destroy (client);
    enet_host_destroy (server);
}

/* Test 7: PMTUD works end to end when ENet packet checksums are enabled. This
 * exercises the checksum-aware framing of probe/ack datagrams (the checksum
 * field sits between the 2-byte header and the command, exactly like normal
 * ENet traffic, so the generic parser authenticates the probes). */
static void
test_with_checksum (void)
{
    ENetHost * server = make_host (1, 4);
    ENetHost * client = make_host (0, 4);
    ENetMtuConfig config;
    ENetPeer * peer;
    ENetMtuStats stats;
    enet_uint32 start;

    printf ("\n[test] path MTU discovery with checksums enabled\n");

    /* Authenticate every datagram on both ends. */
    server -> checksum = enet_crc32;
    client -> checksum = enet_crc32;

    memset (& config, 0, sizeof (config));
    config.enabled = 1;
    config.maxMtu = 1400;
    config.probeTimeout = 100;
    config.maxProbeAttempts = 3;
    config.blackHoleBackoff = 400;
    config.revalidateTime = 0;
    config.allowFragmentation = 1;
    enet_host_enable_mtu_discovery (server, & config);
    enet_host_enable_mtu_discovery (client, & config);

    g_path_mtu = 1200;
    g_blackhole = 0;

    peer = connect_pair (client, server);

    start = enet_time_get ();
    while (enet_time_get () - start < 8000 &&
           peer -> mtuDiscovery.state != ENET_MTU_STATE_CONVERGED)
      pump (client, server, 50);

    enet_peer_get_mtu_stats (peer, & stats);
    print_stats ("client", & stats);
    CHECK (peer -> mtuDiscovery.state == ENET_MTU_STATE_CONVERGED, "converged with checksums enabled");
    CHECK (stats.probesAcked > 0, "authenticated probes were acknowledged under checksums");
    CHECK (stats.probesRejected == 0, "no probe rejected for checksum/framing reasons");
    CHECK (peer -> mtu > ENET_PROTOCOL_MINIMUM_MTU, "MTU raised above the floor under checksums");
    CHECK (peer -> mtu <= g_path_mtu, "confirmed MTU respects the path under checksums");
    CHECK (peer -> state == ENET_PEER_STATE_CONNECTED, "connection usable with checksums and PMTUD");

    enet_host_destroy (client);
    enet_host_destroy (server);
}

int
main (void)
{
    if (enet_initialize () != 0)
    {
        printf ("fatal: enet_initialize failed\n");
        return 2;
    }

    test_default_regression ();
    test_decrease_and_recovery ();
    test_black_hole ();
    test_fragmentation_disabled ();
    test_revalidation_jitter ();
    test_forged_ack_rejected ();
    test_with_checksum ();

    enet_deinitialize ();

    printf ("\n==== %d checks, %d failures ====\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
