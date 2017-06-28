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

/* Handler called when a new raw UDP packet is received */
void read_packet(dtls_context_t *ctx, gnrc_pktsnip_t *pkt)
{
	MEASUREMENT_DTLS_READ_ON;

	session_t session;
	char addr_str[IPV6_ADDR_MAX_STR_LEN];
	gnrc_pktsnip_t *tmp2;

	// Get source address
	tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
	ipv6_hdr_t *hdr = (ipv6_hdr_t *)tmp2->data;
	ipv6_addr_to_str(addr_str, &hdr->src, sizeof(addr_str));

	// Get UDP port
	tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_UDP);
	udp_hdr_t *udp = (udp_hdr_t *)tmp2->data;

	// Create session object
	dtls_session_init(&session);
	session.size = sizeof(ipv6_addr_t);
	session.port = byteorder_ntohs(udp->src_port);
	ipv6_addr_from_str(&session.addr, addr_str);

	// Handle in tinyDTLS
	dtls_handle_message(ctx, &session, pkt->data, (unsigned int)pkt->size);

	MEASUREMENT_DTLS_READ_OFF;
}

/* Called handler function when a new raw packet should be sent */
int handle_write(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len)
{
	ipv6_addr_t addr;
	gnrc_pktsnip_t *payload, *udp, *ip;

	// parse destination address
	if (ipv6_addr_from_str(&addr, UDP_REMOTE_ADDRESS) == NULL) {
		puts("Error: unable to parse destination address");
		return -1;
	}

	// allocate payload
	payload = gnrc_pktbuf_add(NULL, data, len, GNRC_NETTYPE_UNDEF);

	if (payload == NULL) {
		puts("Error: unable to copy data to packet buffer");
		return -1;
	}

	// allocate UDP header
	udp = gnrc_udp_hdr_build(payload, (uint16_t) UDP_LOCAL_PORT, (uint16_t) UDP_REMOTE_PORT);
	if (udp == NULL) {
		puts("Error: Unable to allocate UDP header");
		gnrc_pktbuf_release(payload);
		return -1;
	}

	// allocate IPv6 header
	ip = gnrc_ipv6_hdr_build(udp, NULL,  &addr);
	if (ip == NULL) {
		puts("Error: unable to allocate IPv6 header");
		gnrc_pktbuf_release(udp);
		return -1;
	}

	/*
	 * WARNING: Too fast and the nodes dies in middle of retransmissions.
	 *          This issue appears in the FIT-Lab (m3 motes).
	 *          In native, is not required.
	 */
	//xtimer_usleep(5000);

	/* send packet */
	if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, ip)) {
		puts("Error: unable to locate UDP thread");
		gnrc_pktbuf_release(ip);
		return -1;
	}

	return len;
}

/* Called handler function when a new packet is received */
int handle_read(struct dtls_context_t *context, session_t *session, uint8 *data, size_t length)
{
#ifdef WITH_YACOAP
	// Server
#ifdef WITH_SERVER
	coap_packet_t requestPacket, responsePacket;
	uint8 responseBuffer[DTLS_MAX_BUF];
	size_t responseBufferLength = sizeof(responseBuffer);

	if ((coap_parse(data, length, &requestPacket)) < COAP_ERR)
	{
		// Get data from resources
		coap_handle_request(resources, &requestPacket, &responsePacket);

		// Build response packet
		if ((coap_build(&responsePacket, responseBuffer, &responseBufferLength)) < COAP_ERR)
		{
#ifdef WITH_TINYDTLS
			// Send response packet decrypted over DTLS
			dtls_write(context, session, responseBuffer, responseBufferLength);
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
	(void) context;
	(void) session;
#endif
#endif
	return -1;
}

/* Handler that is called when an event occurs */
int handle_event(struct dtls_context_t *ctx, session_t *session, dtls_alert_level_t level, unsigned short code)
{

#ifndef NDEBUG
	if (code == DTLS_EVENT_CONNECTED) {
		dtls_debug("EVENT Connected!\n");
	}
	else if (code == DTLS_EVENT_CONNECT){
		dtls_debug("EVENT Connecting...\n");
	}else{
		dtls_debug("EVENT Other event occurred!\n");
	}
#endif

	(void) ctx;
	(void) session;
	(void) level;
	(void) code;
	return 0;
}
#endif
