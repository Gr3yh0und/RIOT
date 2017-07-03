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
 * @brief       The server side of TinyDTLS and YaCoAP, partly based on dtls-echo example
 *
 * @author      Raul A. Fuentes Samaniego  <ra.fuentes.sam+RIOT@gmail.com>
 * @author      Olaf Bergmann <bergmann@tzi.org>
 * @author      Hauke Mehrtens <hauke@hauke-m.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @author		Michael Morscher <morscher@hm.edu>
 *
 * @}
 */

#include "dtls-server.h"

#ifdef WITH_TINYDTLS
void *dtls_server_wrapper(void *arg);
dtls_context_t *dtls_context = NULL;
extern dtls_handler_t dtls_callback;
#endif

#ifdef WITH_SERVER
void *server_wrapper(void *arg);

#define READER_QUEUE_SIZE (8U)
static gnrc_netreg_entry_t server = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, KERNEL_PID_UNDEF);
char _server_stack[THREAD_STACKSIZE_MAIN + THREAD_EXTRA_STACKSIZE_PRINTF];
static kernel_pid_t _dtls_kernel_pid;

/**
 * @brief Main loop of insecure CoAP server
 * @param arg:
 */
void *server_wrapper(void *arg){
	msg_t msg;
	printf("Starting insecure server on port: %d\n", UDP_LOCAL_PORT);

#ifdef WITH_YACOAP
	printf("Allocating CoAP resources...");
	resource_setup(resources);
	printf(" Done!\n");
#endif // WITH_YACOAP

	while (1) {
		msg_receive(&msg);
		printf("Message received...\n");
		MEASUREMENT_DTLS_TOTAL_ON;
		read_packet(NULL, (gnrc_pktsnip_t *)(msg.content.ptr));
		gnrc_pktbuf_release(msg.content.ptr);
		MEASUREMENT_DTLS_TOTAL_OFF;
	}
}

/**
 * @brief Creates the server thread
 * @param argc: Amount of arguments given
 * @param argv: List of arguments given
 * @return: >0 = error
 */
int server_thread_create(int argc, char **argv)
{
    uint16_t port;
    port = (uint16_t) UDP_LOCAL_PORT;
    (void) _dtls_kernel_pid;

    // Only one instance of the server
    if (server.target.pid != KERNEL_PID_UNDEF) {
        printf("Error: Server already running!\n");
        return 1;
    }

    // Check if in/secure server thread is started
#ifdef WITH_TINYDTLS
    dtls_init();
    server.target.pid = thread_create(_server_stack, sizeof(_server_stack),
                               THREAD_PRIORITY_MAIN - 1,
                               THREAD_CREATE_STACKTEST,
                               dtls_server_wrapper, NULL, "DTLS CoAP Server");
#else
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
    	printf("Error: UDP port is not registered!\n");
    	return 1;
    }
}

#ifdef WITH_TINYDTLS
#ifdef DTLS_PSK
/**
 * @brief This function is the "key store" for tinyDTLS. It is called to retrieve a key for the given identity within this particular session.
 * @param dtls_context: Pointer to the DTLS context
 * @param session: Pointer to the current session
 * @param id: Pointer to requested ID
 * @param id_length: Length of requested id
 * @param result: Pointer to result object holding the key
 * @param result_length: Length of the key
 * @return:
 */
int get_psk_info(struct dtls_context_t *dtls_context, const session_t *session,
             dtls_credentials_type_t type,
             const unsigned char *id, size_t id_length,
             unsigned char *result, size_t result_length)
{
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
            if (id_length == psk[i].id_length && memcmp(id, psk[i].id, id_length) == 0) {
                if (result_length < psk[i].key_length) {
                    dtls_warn("buffer too small for PSK");
                    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
                }

                memcpy(result, psk[i].key, psk[i].key_length);
                return psk[i].key_length;
            }
        }
    }

    (void) dtls_context;
    (void) session;
    return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}
#endif /* DTLS_PSK */

/**
 * @brief Initialising server and main loop
 * @param arg: Not used
 */
void *dtls_server_wrapper(void *arg)
{
    msg_t _reader_queue[READER_QUEUE_SIZE];
    msg_t msg;
    msg_init_queue(_reader_queue, READER_QUEUE_SIZE);
    printf("Starting secure server on port: %d\n", UDP_LOCAL_PORT);

#ifdef WITH_YACOAP
	printf("Allocating CoAP resources...");
	resource_setup(resources);
	printf(" Done!\n");
#endif // WITH_YACOAP

	// Init TinyDTLS
	char *addr_str = "::1";
	dtls_set_log_level(DTLS_LOG_EMERG);
	dtls_context = dtls_new_context(addr_str);
	if (dtls_context) {
		dtls_set_handler(dtls_context, &dtls_callback);
	}else{
		printf("Error: Server was unable to generate DTLS Context!\n");
		exit(-1);
	}

	// Main Loop: Wait for message, hand it over to DTLS and discard it
    while (1) {
        msg_receive(&msg);
        printf("Message received...\n");
        MEASUREMENT_DTLS_TOTAL_ON;
        read_packet(dtls_context, (gnrc_pktsnip_t *)(msg.content.ptr));
        gnrc_pktbuf_release(msg.content.ptr);
        MEASUREMENT_DTLS_TOTAL_OFF;
    }

    dtls_free_context(dtls_context);
    (void) arg;
}
#endif // WITH_TINYDTLS

#endif // WITH_SERVER
