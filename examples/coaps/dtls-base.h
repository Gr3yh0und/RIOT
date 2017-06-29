/*
 * dtls_base.h
 *
 *  Base class for DTLS client and server connections
 *  Partly based on the RIOT DTLS example by Raul Fuentes
 *
 *  Created on: 15 Jun 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#ifndef EXAMPLES_COAPS_DTLS_BASE_H_
#define EXAMPLES_COAPS_DTLS_BASE_H_

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "net/gnrc/pktdump.h"

#include "measurement.h"

#ifdef WITH_TINYDTLS
#include "dtls.h"
#include "dtls_debug.h"
#endif

#ifdef WITH_SERVER
#include "dtls-server.h"
#endif
#ifdef WITH_CLIENT
#include "dtls-client.h"
#endif

#ifdef WITH_YACOAP
#include "coap.h"
#endif

#ifndef WITH_CONSOLE
#define printf(...)
#endif

// Definition of server ip address and ports
#define UDP_LOCAL_PORT 		6666
#define UDP_REMOTE_PORT 	7777
#define UDP_REMOTE_ADDRESS 	"fd00:dead:beef::1"

// DTLS configuration
#define DTLS_DEBUG_LEVEL 	DTLS_LOG_DEBUG
#define MAIN_QUEUE_SIZE     (16)
#ifndef DTLS_MAX_BUF
#define DTLS_MAX_BUF 		100
#endif

// YaCoAP variables
#ifdef WITH_YACOAP
extern void resource_setup(const coap_resource_t *resources);
extern coap_resource_t resources[];
#endif

// DTLS defines
#if defined DTLS_CONF_IDENTITY_HINT && defined DTLS_CONF_IDENTITY_HINT_LENGTH
#define DTLS_IDENTITY_HINT DTLS_CONF_IDENTITY_HINT
#define DTLS_IDENTITY_HINT_LENGTH DTLS_CONF_IDENTITY_HINT_LENGTH
#else
#define DTLS_IDENTITY_HINT "Client_identity"
#define DTLS_IDENTITY_HINT_LENGTH 15
#endif

#if defined DTLS_CONF_PSK_KEY && defined DTLS_CONF_PSK_KEY_LENGTH
#define DTLS_PSK_KEY_VALUE DTLS_CONF_PSK_KEY
#define DTLS_PSK_KEY_VALUE_LENGTH DTLS_CONF_PSK_KEY_LENGTH
#else
#define DTLS_PSK_KEY_VALUE "secretPSK"
#define DTLS_PSK_KEY_VALUE_LENGTH 9
#endif

// Functions used by secure client and server
#ifdef WITH_TINYDTLS
void read_packet(dtls_context_t *ctx, gnrc_pktsnip_t *pkt);
int handle_write(struct dtls_context_t *ctx, session_t *session, uint8 *data, size_t len);
int handle_read(struct dtls_context_t *context, session_t *session, uint8 *data, size_t length);
int handle_event(struct dtls_context_t *ctx, session_t *session, dtls_alert_level_t level, unsigned short code);
extern int get_psk_info(struct dtls_context_t *ctx,
                        const session_t *session,
                        dtls_credentials_type_t type,
                        const unsigned char *id, size_t id_len,
                        unsigned char *result, size_t result_length);
#endif // WITH_TINYDTLS

// Function used by insecure server
int send_packet(char *peerIpString, char *data, size_t dataLength, unsigned short peerPort);

#endif /* EXAMPLES_COAPS_DTLS_BASE_H_ */
