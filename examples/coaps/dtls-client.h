/*
 * dtls-client.h
 *
 *  Created on: 21 May 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#ifndef EXAMPLES_COAPS_DTLS_CLIENT_H_
#define EXAMPLES_COAPS_DTLS_CLIENT_H_

#include "msg.h"
#include "net/af.h"
#include "net/conn/udp.h"
#include "net/ipv6/addr.h"

#include "dtls.h"
#include "measurement.h"
#include "dtls-base.h"

#if defined(DTLS_PSK) && defined(WITH_TINYDTLS) && defined(WITH_CLIENT)
int get_psk_info(struct dtls_context_t *ctx,
                        const session_t *session,
                        dtls_credentials_type_t type,
                        const unsigned char *id, size_t id_len,
                        unsigned char *result, size_t result_length);
int client_thread_create(int argc, char **argv);
#endif

#endif /* EXAMPLES_COAPS_DTLS_CLIENT_H_ */
