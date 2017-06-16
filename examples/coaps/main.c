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
 * @brief       Example application  for TinyDTLS
 *
 * @author      Raul Fuentes <>
 *
 * @}
 */

#include <stdio.h>
#include "xtimer.h"

// networking
#include "msg.h"
#include "net/af.h"
#include "net/conn/udp.h"
#include "net/ipv6/addr.h"

// application
#include "measurement.h"

#define DTLS_DEBUG_LEVEL 	DTLS_LOG_DEBUG
#define SEND_INTERVAL 		(1 * CLOCK_SECOND)
#define MAIN_QUEUE_SIZE     (8)

#ifdef WITH_TINYDTLS
#include "dtls-base.h"
#endif

#ifdef WITH_CLIENT
static session_t session;
static conn_udp_t connection;
static dtls_context_t *dtls_context;
#endif

#ifdef RIOT_SHELL
#include "shell.h"
extern int udp_client_cmd(int argc, char **argv);
extern int udp_server_cmd(int argc, char **argv);
static const shell_command_t shell_commands[] = {
    { "dtlss", "Start a DTLS server (with echo)", udp_server_cmd },
    { NULL, NULL, NULL }
};
#endif

/* Definition of executed handlers */
dtls_handler_t dtls_callback = {
  .write = handle_write,
  .read  = handle_read,
  .event = handle_event,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif
};

extern int _netif_config(int argc, char **argv);
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void)
{
    // Message queue is needed for many packets at once
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    // Print local IP address
    printf("Waiting for IP...");
	kernel_pid_t interface[GNRC_NETIF_NUMOF];
	char ipAddress[IPV6_ADDR_MAX_STR_LEN];
	size_t numberOfInterfaces = gnrc_netif_get(interface);
	if (numberOfInterfaces > 0) {
		gnrc_ipv6_netif_t *entry = gnrc_ipv6_netif_get(interface[0]);
		ipv6_addr_to_str(ipAddress, &entry->addrs[3].addr, IPV6_ADDR_MAX_STR_LEN);
		while(strcmp(ipAddress, "fd00::212:4b00:615:a86b")){
			ipv6_addr_to_str(ipAddress, &entry->addrs[3].addr, IPV6_ADDR_MAX_STR_LEN);
		}
	}
	printf("%s\n", ipAddress);

#ifdef RIOT_SHELL
    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
#endif

#ifdef GPIO_OUTPUT_ENABLE
    measurement_init_gpio();
#endif

#ifdef WITH_CLIENT
	// Setup client UDP
    printf("Setting up UDP...\n");
	session.size = sizeof(session.addr);
	session.port = UDP_REMOTE_PORT;
	ipv6_addr_from_str(&session.addr, UDP_REMOTE_ADDRESS);

	// Start client UDP connection
    ipv6_addr_t src = IPV6_ADDR_UNSPECIFIED, dst;
    ipv6_addr_from_str(&dst, UDP_REMOTE_ADDRESS);
	conn_udp_create(&connection, &src, sizeof(src), AF_INET6, UDP_LOCAL_PORT);

	msg_t msg;
	static uint8 buffer[32];
	static size_t bufferLength = sizeof(buffer);

#ifdef WITH_YACOAP
	static coap_packet_t requestPacket;
	static uint8 messageId = 42;

#ifdef WITH_CLIENT_PUT
	// PUT light
	printf("Client with PUT...\n");
	static coap_resource_path_t resourcePath = {1, {"light"}};
	static coap_resource_t request = {COAP_RDY, COAP_METHOD_PUT, COAP_TYPE_CON, NULL, &resourcePath, COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_TXT_PLAIN)};
	coap_make_request(messageId, NULL, &request, &messageId, sizeof(messageId), &requestPacket);
#else
	// GET time
	printf("Client with GET...\n");
	static coap_resource_path_t resourcePath = {1, {"time"}};
	static coap_resource_t request = {COAP_RDY, COAP_METHOD_GET, COAP_TYPE_CON, NULL, &resourcePath, COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_TXT_PLAIN)};
	coap_make_request(messageId, NULL, &request, NULL, 0, &requestPacket);
#endif

	coap_build(&requestPacket, buffer, &bufferLength);
#endif
#endif

#ifdef WITH_SERVER
    start_server();
#endif

#if defined(WITH_TINYDTLS) && defined(WITH_CLIENT)
	// Setup DTLS
    printf("Initializing DTLS...\n");
	dtls_set_log_level(DTLS_DEBUG_LEVEL);
	dtls_context = dtls_new_context(&connection);

	if (dtls_context)
		dtls_set_handler(dtls_context, &dtls_callback);

	dtls_init();
	if (!dtls_context) {
		printf("cannot create context\n");
	    return 1;
	}
#endif

#ifdef WITH_CLIENT
	int counter = 0;
	while(1) {
		counter++;
#ifdef WITH_TINYDTLS
		if (msg_try_receive(&msg) == 1) {
			onUdpPacket(dtls_context, (gnrc_pktsnip_t *)(msg.content.ptr));
		}
#ifdef WITH_CLIENT
		if(counter == 100000){
			puts(".");
			MEASUREMENT_DTLS_TOTAL_ON;
			MEASUREMENT_DTLS_WRITE_ON;
			dtls_write(dtls_context, &session, buffer, bufferLength);
			MEASUREMENT_DTLS_WRITE_OFF;
			counter = 0;
		}
#endif
	#endif
		}
#endif

    return 0;
}
