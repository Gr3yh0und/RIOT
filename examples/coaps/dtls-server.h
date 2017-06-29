/*
 * dtls_server.h
 *
 *  Server specific implementation
 *  Partly based on the RIOT DTLS example by Raul Fuentes
 *
 *  Created on: 16 May 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#ifndef EXAMPLES_COAPS_DTLS_SERVER_H_
#define EXAMPLES_COAPS_DTLS_SERVER_H_

#include "dtls-base.h"

#ifdef WITH_SERVER
int server_thread_create(int argc, char **argv);

#if defined(WITH_TINYDTLS) && defined(DTLS_PSK)
int get_psk_info(struct dtls_context_t *ctx, const session_t *session,
						 dtls_credentials_type_t type,
						 const unsigned char *id, size_t id_len,
						 unsigned char *result, size_t result_length);
#endif // WITH_TINYDTLS
#endif // WITH_SERVER

#endif /* EXAMPLES_COAPS_DTLS_SERVER_H_ */
