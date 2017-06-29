/*
 * dtls_base.c
 *
 *  Base class for DTLS client and server connections
 *  Partly based on the RIOT DTLS example by Raul Fuentes
 *
 *  Created on: 15 Jun 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#include "dtls-base.h"

#ifdef WITH_TINYDTLS
/* Definition of executed handlers */
dtls_handler_t dtls_callback = {
  .write = handle_write,
  .read  = handle_read,
  .event = handle_event,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif
};

/**
 * Handler called when a new raw UDP packet is received
 * @param dtls_context: Pointer to DTLS context
 * @param packet: Pointer to incoming message
 */
void read_packet(dtls_context_t *dtls_context, gnrc_pktsnip_t *packet)
{
	MEASUREMENT_DTLS_READ_ON;

	session_t session;
	char ipAddress[IPV6_ADDR_MAX_STR_LEN];
	gnrc_pktsnip_t *snippet;

	// Get remote IPv6 address
	snippet = gnrc_pktsnip_search_type(packet, GNRC_NETTYPE_IPV6);
	ipv6_hdr_t *ipHeader = (ipv6_hdr_t *)snippet->data;
	ipv6_addr_to_str(ipAddress, &ipHeader->src, sizeof(ipAddress));
#ifdef WITH_SERVER
	dtls_context->app = ipAddress;
#endif

	// Get remote UDP port
	snippet = gnrc_pktsnip_search_type(packet, GNRC_NETTYPE_UDP);
	udp_hdr_t *udpHeader = (udp_hdr_t *)snippet->data;

	// Create session object
	dtls_session_init(&session);
	session.size = sizeof(ipv6_addr_t);
	session.port = byteorder_ntohs(udpHeader->src_port);
	ipv6_addr_from_str(&session.addr, ipAddress);

	// Handle in tinyDTLS
	dtls_handle_message(dtls_context, &session, packet->data, (unsigned int) packet->size);

	MEASUREMENT_DTLS_READ_OFF;
}

/**
 * Automatically called handler function when a new raw packet should be sent
 * @param dtls_context: Pointer to DTLS context
 * @param session: Pointer to current session object (with peer)
 * @param data: Pointer to message payload
 * @param length: Length of message payload
 * @return:
 *
 */
int handle_write(struct dtls_context_t *dtls_context, session_t *session, uint8 *data, size_t length)
{
	(void) dtls_context;
	(void) session;
	return send_packet(UDP_REMOTE_ADDRESS, (char*) data, length, UDP_REMOTE_PORT);
}

/**
 * Automatically called handler function when a new packet is received
 * @param dtls_context: Pointer to DTLS context
 * @param session: Pointer to current session object (with peer)
 * @param data: Pointer to message payload
 * @param length: Length of message payload
 * @return:
 */
int handle_read(struct dtls_context_t *dtls_context, session_t *session, uint8 *data, size_t length)
{

#ifdef WITH_YACOAP
	// Server
#ifdef WITH_SERVER
	coap_packet_t requestPacket, responsePacket;
	uint8 responseBuffer[DTLS_MAX_BUF];
	size_t responseBufferLength = sizeof(responseBuffer);

	// Parse raw data for CoAP content
	if ((coap_parse(data, length, &requestPacket)) < COAP_ERR)
	{
		// Get data from resources
		coap_handle_request(resources, &requestPacket, &responsePacket);

		// Build response packet
		if ((coap_build(&responsePacket, responseBuffer, &responseBufferLength)) < COAP_ERR)
		{
#ifdef WITH_TINYDTLS
			// Send response packet encrypted over DTLS
			MEASUREMENT_DTLS_WRITE_ON;
			dtls_write(dtls_context, session, responseBuffer, responseBufferLength);
			MEASUREMENT_DTLS_WRITE_OFF;
			return 0;
#endif
		}
	}
#endif

	// Client
#ifdef WITH_CLIENT
	MEASUREMENT_DTLS_TOTAL_OFF;
	coap_packet_t packet;
	coap_parse(data, length, &packet);
	printf("(COAP) Answer was: %.*s\n", packet.payload.len, (char *)packet.payload.p);
	(void) dtls_context;
	(void) session;
#endif
#endif
	return -1;
}

/**
 * Handler that is automatically called when an event occurs
 * @param dtls_context: Pointer to DTLS context
 * @param session: Pointer to current session object (with peer)
 * @param level:
 * @param code:
 * @return:
 */
int handle_event(struct dtls_context_t *dtls_context, session_t *session, dtls_alert_level_t level, unsigned short code)
{

#ifndef NDEBUG
	if (code == DTLS_EVENT_CONNECTED) {
		dtls_debug("EVENT Connected!\n");
	}else if (code == DTLS_EVENT_CONNECT){
		dtls_debug("EVENT Connecting...\n");
	}else{
		dtls_debug("EVENT Other event occurred!\n");
	}
#endif

	(void) dtls_context;
	(void) session;
	(void) level;
	(void) code;
	return 0;
}
#endif // WITH_TINYDTLS

/**
 * Transmits a packet with given data to a given address/port
 * @param addr_str: Pointer to IP address as character
 * @param data: Pointer to data
 * @param data_len: Length of data
 * @param rem_port: Port number at remote address
 * @return:
 */
int send_packet(char *peerIpString, char *data, size_t dataLength, unsigned short peerPort)
{
	MEASUREMENT_DTLS_WRITE_ON;

    ipv6_addr_t peerIp;
    gnrc_pktsnip_t *packetPayload, *packetUdp, *packetIp;

    // Parse destination address
    if(ipv6_addr_from_str(&peerIp, peerIpString) == NULL) {
        printf("Error: Unable to parse destination address!\n");
        return -1;
    }

    // Allocate payload
    packetPayload = gnrc_pktbuf_add(NULL, data, dataLength, GNRC_NETTYPE_UNDEF);
    if(packetPayload == NULL) {
        printf("Error: Unable to copy data to packet buffer!\n");
        return -1;
    }

    // Allocate UDP header
    packetUdp = gnrc_udp_hdr_build(packetPayload, UDP_LOCAL_PORT, peerPort);
    if(packetUdp == NULL) {
        printf("Error: Unable to allocate UDP header!\n");
        gnrc_pktbuf_release(packetPayload);
        return -1;
    }

    // Allocate IPv6 header
    packetIp = gnrc_ipv6_hdr_build(packetUdp, NULL, &peerIp);
    if(packetIp == NULL) {
        printf("Error: Unable to allocate IPv6 header!\n");
        gnrc_pktbuf_release(packetUdp);
        return -1;
    }

    // Send assembled packet
    printf("Sending packet to peer %s ...\n", peerIpString);
    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, packetIp)) {
        puts("Error: unable to locate UDP thread");
        gnrc_pktbuf_release(packetIp);
        return -1;
    }

    MEASUREMENT_DTLS_WRITE_OFF;
    return 1;
}
