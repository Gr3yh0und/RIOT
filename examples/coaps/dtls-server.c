/*
 * Copyright (C) 2015 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       The server side of TinyDTLS (Simple echo)
 *
 * @author      Raul A. Fuentes Samaniego  <ra.fuentes.sam+RIOT@gmail.com>
 * @author      Olaf Bergmann <bergmann@tzi.org>
 * @author      Hauke Mehrtens <hauke@hauke-m.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include <inttypes.h>

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "timex.h"
#include "xtimer.h"
#include "msg.h"
#include "measurement.h"

/* TinyDTLS */
#ifdef WITH_TINYDTLS
#include "dtls.h"
#include "dtls_debug.h"
#include "tinydtls.h"
void *dtls_server_wrapper(void *arg);
dtls_context_t *dtls_context = NULL;
#endif

/* YaCoap */
#ifdef WITH_YACOAP
#include "coap.h"
#endif

#define ENABLE_DEBUG  (1)
#include "debug.h"

#ifdef WITH_TINYDTLS_PORT
#define DEFAULT_PORT WITH_TINYDTLS_PORT
#else
#define DEFAULT_PORT 6666
#endif

#ifdef WITH_SERVER
#include "dtls-base.h"

#define READER_QUEUE_SIZE (8U)
static gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, KERNEL_PID_UNDEF);
char _server_stack[THREAD_STACKSIZE_MAIN + THREAD_EXTRA_STACKSIZE_PRINTF];
static kernel_pid_t _dtls_kernel_pid;

/* YaCoap */
#ifdef WITH_YACOAP
extern void resource_setup(const coap_resource_t *resources);
extern coap_resource_t resources[];
#endif // WITH_YACOAP

/**
 * @brief This will try to transmit using only GNRC stack (non-socket).
 */
static int gnrc_sending(char *addr_str, char *data, size_t data_len, unsigned short rem_port)
{
    ipv6_addr_t addr;
    gnrc_pktsnip_t *payload, *udp, *ip;

    /* parse destination address */
    if (ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("Error: unable to parse destination address");
        return -1;
    }

    payload = gnrc_pktbuf_add(NULL, data, data_len, GNRC_NETTYPE_UNDEF);

    if (payload == NULL) {
        puts("Error: unable to copy data to packet buffer");
        return -1;
    }

    /* allocate UDP header */
    udp = gnrc_udp_hdr_build(payload, DEFAULT_PORT, rem_port);
    if (udp == NULL) {
        puts("Error: unable to allocate UDP header");
        gnrc_pktbuf_release(payload);
        return -1;
    }

    /* allocate IPv6 header */
    ip = gnrc_ipv6_hdr_build(udp, NULL, &addr);
    if (ip == NULL) {
        puts("Error: unable to allocate IPv6 header");
        gnrc_pktbuf_release(udp);
        return -1;
    }
    /* send packet */

    DEBUG("DBG-Server: Sending record to peer\n");

    /*
     * WARNING: Too fast and the nodes dies in middle of retransmissions.
     *         This issue appears in the FIT-Lab (m3 motes).
     */
    //xtimer_usleep(500000);

    /* Probably this part will be removed.  **/
    if (!gnrc_netapi_dispatch_send(GNRC_NETTYPE_UDP, GNRC_NETREG_DEMUX_CTX_ALL, ip)) {
        puts("Error: unable to locate UDP thread");
        gnrc_pktbuf_release(ip);
        return -1;
    }

    return 1;
}

void *server_wrapper(void *arg){
	msg_t msg;
	while (1) {
		msg_receive(&msg);
		MEASUREMENT_DTLS_TOTAL_ON;
		printf("Message received...\n");

#ifdef WITH_YACOAP
		coap_packet_t requestPacket, responsePacket;
		uint8_t responseBuffer[DTLS_MAX_BUF];
		size_t responseBufferLength = sizeof(responseBuffer);

		// Get data from message
		gnrc_pktsnip_t *pkt = msg.content.ptr;
		gnrc_pktsnip_t *tmp2;

		// Extract port
		tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_UDP);
		udp_hdr_t *udp = (udp_hdr_t *)tmp2->data;

		// Extract ip address
		tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
		ipv6_hdr_t *hdr = (ipv6_hdr_t *)tmp2->data;
		char addr_str[IPV6_ADDR_MAX_STR_LEN];
		ipv6_addr_to_str(addr_str, &hdr->src, sizeof(addr_str));
		MEASUREMENT_DTLS_READ_OFF;

		if ((coap_parse(pkt->data, (unsigned int)pkt->size, &requestPacket)) < COAP_ERR)
		{
			// Get data from resources
			coap_handle_request(resources, &requestPacket, &responsePacket);

			// Build response packet
			if ((coap_build(&responsePacket, responseBuffer, &responseBufferLength)) < COAP_ERR)
			{
				// Send response packet
				MEASUREMENT_DTLS_WRITE_ON;
				printf("Sending response...\n");
				gnrc_sending(addr_str, (char*)responseBuffer, responseBufferLength, byteorder_ntohs(udp->src_port));
				MEASUREMENT_DTLS_WRITE_OFF;
			}
		}
#endif // WITH_YACOAP
		MEASUREMENT_DTLS_TOTAL_OFF;

	}
}

int server_thread_create(int argc, char **argv)
{
    uint16_t port;
    port = (uint16_t)DEFAULT_PORT;
    (void) _dtls_kernel_pid;

    /* Only one instance of the server */
    if (server.target.pid != KERNEL_PID_UNDEF) {
        printf("Error: server already running\n");
        return 1;
    }

#ifdef WITH_TINYDTLS
    dtls_init();

    /* The server is initialized  */
    server.target.pid = thread_create(_server_stack, sizeof(_server_stack),
                               THREAD_PRIORITY_MAIN - 1,
                               THREAD_CREATE_STACKTEST,
                               dtls_server_wrapper, NULL, "DTLS CoAP Server");
#else
    /* The server is initialized  */
	server.target.pid = thread_create(_server_stack, sizeof(_server_stack),
							   THREAD_PRIORITY_MAIN - 1,
							   THREAD_CREATE_STACKTEST,
							   server_wrapper, NULL, "CoAP Server");
#endif

    server.demux_ctx = (uint32_t)port;

    if (gnrc_netreg_register(GNRC_NETTYPE_UDP, &server) == 0){
    	printf("Success: started server on port %" PRIu16 "\n", port);
    	return 0;
    }else{
    	printf("FAILURE: The UDP port is not registered!\n");
    	return 1;
    }
}

// TinyDTLS
#ifdef WITH_TINYDTLS

/**
 * @brief This care about getting messages and continue with the DTLS flights
 */
static void dtls_handle_read(dtls_context_t *ctx, gnrc_pktsnip_t *pkt)
{
    static session_t session;

    /*
     * NOTE: GNRC (Non-socket) issue: we need to modify the current
     * DTLS Context for the IPv6 src (and in a future the port src).
     */

    /* Taken from the tftp server example */
    char addr_str[IPV6_ADDR_MAX_STR_LEN];
    gnrc_pktsnip_t *tmp2;

    tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_IPV6);
    ipv6_hdr_t *hdr = (ipv6_hdr_t *)tmp2->data;

    ipv6_addr_to_str(addr_str, &hdr->src, sizeof(addr_str));
    /* This is unique to the server (Non-socket) */
    ctx->app = addr_str;

    /*
     * TODO: More testings with TinyDTLS is neccesary, but seem this is safe.
     */
    tmp2 = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_UDP);
    udp_hdr_t *udp = (udp_hdr_t *)tmp2->data;

    session.size = sizeof(ipv6_addr_t) + sizeof(unsigned short);
    session.port = byteorder_ntohs(udp->src_port);

    ipv6_addr_from_str(&session.addr, addr_str);

    dtls_handle_message(ctx, &session, pkt->data, (unsigned int)pkt->size);
}

/**
 * @brief We got the TinyDTLS App Data message and answer with the same
 */
static int read_from_peer(struct dtls_context_t *context, session_t *session, uint8 *data, size_t length)
{
#ifdef WITH_YACOAP
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
			// Send response packet decrypted over DTLS
			MEASUREMENT_DTLS_WRITE_ON;
			dtls_write(context, session, responseBuffer, responseBufferLength);
			MEASUREMENT_DTLS_WRITE_OFF;
		}
	}
#endif // WITH_YACOAP

	return 0;
}

/**
 * @brief We communicate with the other peer.
 */
static int send_to_peer(struct dtls_context_t *ctx, session_t *session, uint8 *buf, size_t len)
{
    (void) session;

    /*FIXME TODO: dtls_get_app_data(ctx) should have the remote port! */
    char *addr_str;
    addr_str = (char *)dtls_get_app_data(ctx);

    gnrc_sending(addr_str, (char *)buf, len, session->port);

    return len;
}

#ifdef DTLS_PSK
int get_psk_info(struct dtls_context_t *ctx, const session_t *session,
         dtls_credentials_type_t type,
         const unsigned char *id, size_t id_len,
         unsigned char *result, size_t result_length)
{

	struct keymap_t {
		unsigned char *id;
		size_t id_length;
		unsigned char *key;
		size_t key_length;
	} psk[1] = {
			{ (unsigned char *)DTLS_IDENTITY_HINT, DTLS_IDENTITY_HINT_LENGTH,
					(unsigned char *)DTLS_PSK_KEY_VALUE, DTLS_PSK_KEY_VALUE_LENGTH },
	};

	if (type != DTLS_PSK_KEY) {
	  return 0;
	}

	if (id) {
		int i;
		for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) {
			if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
				if (result_length < psk[i].key_length) {
					dtls_warn("buffer too small for PSK");
					return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
				}

				memcpy(result, psk[i].key, psk[i].key_length);
				return psk[i].key_length;
			}
		}
	}

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int peer_get_psk_info(struct dtls_context_t *ctx, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_len,
             unsigned char *result, size_t result_length)
{
    (void) ctx;
    (void) session;
    struct keymap_t {
        unsigned char *id;
        size_t id_length;
        unsigned char *key;
        size_t key_length;
    } psk[3] = {
        { (unsigned char *)"Client_identity", 15,
          (unsigned char *)"secretPSK", 9 },
        { (unsigned char *)"default identity", 16,
          (unsigned char *)"\x11\x22\x33", 3 },
        { (unsigned char *)"\0", 2,
          (unsigned char *)"", 1 }
    };

    if (type != DTLS_PSK_KEY) {
        return 0;
    }

    if (id) {
        unsigned int i;
        for (i = 0; i < sizeof(psk) / sizeof(struct keymap_t); i++) {
            if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) {
                if (result_length < psk[i].key_length) {
                    dtls_warn("buffer too small for PSK");
                    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
                }

                memcpy(result, psk[i].key, psk[i].key_length);
                return psk[i].key_length;
            }
        }
    }

    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

/* NOTE: wrapper or trampoline ? (Syntax question) */
void *dtls_server_wrapper(void *arg)
{
    (void) arg; /* TODO: Remove? We don't have args at all (NULL) */

    msg_t _reader_queue[READER_QUEUE_SIZE];
    msg_t msg;

    /* The GNRC examples uses packet dump but we want a custom one */
    msg_init_queue(_reader_queue, READER_QUEUE_SIZE);

    static dtls_handler_t cb = {
    		.write = send_to_peer,
            .read  = read_from_peer,
            .event = NULL,
    #ifdef DTLS_PSK
            .get_psk_info = peer_get_psk_info,
    #endif  /* DTLS_PSK */
        };

    DEBUG("Note: DEBUG activated\n");

#ifdef WITH_YACOAP
	// Initialise COAP resources
	printf("Allocating CoAP resources...");
	resource_setup(resources);
	printf(" Done!\n");
#endif // WITH_YACOAP

	/*
	 * The context for the server is a little different from the client.
	 * The simplicity of GNRC do not mix transparently with
	 * the DTLS Context. At this point, the server need a fresh context
	 * however dtls_context->app must be populated with an unknown
	 * IPv6 address.
	 *
	 * The non-valid Ipv6 address ( :: ) is discarded due the chaos.
	 * For now, the first value will be the loopback.
	 */
	char *addr_str = "::1";

	dtls_set_log_level(DTLS_LOG_EMERG);

	dtls_context = dtls_new_context(addr_str);
	if (dtls_context) {
		dtls_set_handler(dtls_context, &cb);
	}
	else {
		puts("Server was unable to generate DTLS Context!");
		exit(-1);
	}

    /*
     * FIXME: After mutliple retransmissions, and canceled client's sessions
     * the server become unable to sent NDP NA messages. Still, the TinyDTLS
     * debugs seems to be fine.
     */
    while (1) {
        /* wait for a message */
        msg_receive(&msg);

        DEBUG("DBG-Server: Record Rcvd!\n");
        dtls_handle_read(dtls_context, (gnrc_pktsnip_t *)(msg.content.ptr));
        gnrc_pktbuf_release(msg.content.ptr);
    }

    dtls_free_context(dtls_context);
}
#endif // WITH_TINYDTLS

#endif // WITH_SERVER
