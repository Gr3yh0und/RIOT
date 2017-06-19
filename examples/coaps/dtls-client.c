/*
 * dtls-client.c
 *
 *  Created on: 21 May 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#include "dtls-client.h"

#if defined(DTLS_PSK) && defined(WITH_TINYDTLS) && defined(WITH_CLIENT)
#define PSK_DEFAULT_IDENTITY DTLS_IDENTITY_HINT
#define PSK_DEFAULT_KEY      DTLS_PSK_KEY_VALUE
#define PSK_OPTIONS          "i:k:"

/* Max size for PSK lowered for embedded devices */
#define PSK_ID_MAXLEN 32
#define PSK_MAXLEN 32

static unsigned char psk_id[PSK_ID_MAXLEN] = PSK_DEFAULT_IDENTITY;
static size_t psk_id_length = sizeof(PSK_DEFAULT_IDENTITY) - 1;
static unsigned char psk_key[PSK_MAXLEN] = PSK_DEFAULT_KEY;
static size_t psk_key_length = sizeof(PSK_DEFAULT_KEY) - 1;

extern dtls_handler_t dtls_callback;

/**
 * This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session.
 */
int get_psk_info(struct dtls_context_t *ctx,
                        const session_t *session,
                        dtls_credentials_type_t type,
                        const unsigned char *id, size_t id_len,
                        unsigned char *result, size_t result_length)
{

    switch (type) {
        case DTLS_PSK_IDENTITY:
               if (id_len) {
               dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
               }

            if (result_length < psk_id_length) {
                dtls_warn("cannot set psk_identity -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_id, psk_id_length);
            return psk_id_length;
        case DTLS_PSK_KEY:
            if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
                dtls_warn("PSK for unknown id requested, exiting\n");
                return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
            }
            else if (result_length < psk_key_length) {
                dtls_warn("cannot set psk -- buffer too small\n");
                return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
            }

            memcpy(result, psk_key, psk_key_length);
            return psk_key_length;
        default:
            dtls_warn("unsupported request type: %d\n", type);
    }

    (void) ctx;
    (void) session;
    return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}

static session_t session;
static conn_udp_t connection;
static dtls_context_t *dtls_context;
char client_thread_stack[THREAD_STACKSIZE_MAIN];
void client_thread_start(void);
static msg_t _client_msg_queue[MAIN_QUEUE_SIZE];

/**
 * Client Thread
 */
void *client_thread(void *arg){
	(void) arg;

	// Message queue is needed for many packets at once
	msg_init_queue(_client_msg_queue, MAIN_QUEUE_SIZE);

	// Setup client UDP
    printf("Setting up UDP... ");
	session.size = sizeof(session.addr);
	session.port = UDP_REMOTE_PORT;
	ipv6_addr_from_str(&session.addr, UDP_REMOTE_ADDRESS);

	// Start client UDP connection
    ipv6_addr_t src = IPV6_ADDR_UNSPECIFIED, dst;
    ipv6_addr_from_str(&dst, UDP_REMOTE_ADDRESS);
	conn_udp_create(&connection, &src, sizeof(src), AF_INET6, UDP_LOCAL_PORT);
	printf("Done!\n");

	msg_t msg;
	static uint8 buffer[32];
	static size_t bufferLength = sizeof(buffer);

#ifdef WITH_YACOAP
	static coap_packet_t requestPacket;
	static uint8 messageId = 0;

#ifdef WITH_CLIENT_PUT
	// PUT status
	printf("Client with PUT...\n");
	static coap_resource_path_t resourcePath = {1, {"status"}};
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

#ifdef WITH_TINYDTLS
	// Setup DTLS
    printf("Initialising DTLS... ");
	dtls_set_log_level(DTLS_DEBUG_LEVEL);
	dtls_context = dtls_new_context(&connection);

	if (dtls_context)
		dtls_set_handler(dtls_context, &dtls_callback);

	dtls_init();
	if (!dtls_context) {
		printf("cannot create context\n");
		exit(1);
	}
	printf("Done!\n");
#endif

	// Main client logic
	int counter = 0;
	while(1) {
		counter++;
#ifdef WITH_TINYDTLS
		if (msg_try_receive(&msg) == 1) {
			onUdpPacket(dtls_context, (gnrc_pktsnip_t *)(msg.content.ptr));
		}
		if(counter == 175000){
			//puts(".");
			MEASUREMENT_DTLS_TOTAL_ON;
			MEASUREMENT_DTLS_WRITE_ON;
			dtls_write(dtls_context, &session, buffer, bufferLength);
			MEASUREMENT_DTLS_WRITE_OFF;
			counter = 0;
		}
	}
#endif
	return NULL;
}

/**
 * Creation of client thread
 */
int client_thread_create(int argc, char **argv){
	thread_create(client_thread_stack, sizeof(client_thread_stack), THREAD_PRIORITY_MAIN, THREAD_CREATE_STACKTEST, client_thread, NULL, "DTLS Client");
	return 0;
}

#endif
