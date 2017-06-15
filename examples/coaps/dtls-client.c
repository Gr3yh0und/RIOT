/*
 * dtls-client.c
 *
 *  Created on: 21 May 2017
 *      Author: Michael Morscher, morscher@hm.edu
 */

#include "dtls-base.h"

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
#endif
