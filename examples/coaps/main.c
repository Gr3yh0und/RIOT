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

#include "msg.h"

#ifdef RIOT_SHELL
#include "shell.h"
#endif

#ifdef RIOT_WITH_TINYDTLS
#include "dtls-server.h"
#endif

/* TinyDTLS WARNING check */
#ifdef WITH_RIOT_SOCKETS
#error TinyDTLS is configured for working with Sockets. Yet, this is non-socket
#endif

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

#ifdef RIOT_SHELL
extern int udp_client_cmd(int argc, char **argv);
extern int udp_server_cmd(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "dtlsc", "Start a DTLS client", udp_client_cmd },
    { "dtlss", "Start a DTLS server (with echo)", udp_server_cmd },
    { NULL, NULL, NULL }
};
#endif

int main(void)
{
    /* we need a message queue for the thread running the shell in order to
     * receive potentially fast incoming networking packets */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

#ifdef RIOT_SHELL
    start_server();

    /* start shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
#endif


    return 0;
}
