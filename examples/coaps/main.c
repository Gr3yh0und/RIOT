/*
 * Copyright (C) 2015 Freie Universität Berlin
 * Copyright (C) 2017 Hochschule München
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
 * @brief       DTLS Server and client wrapper, partly based on DTLS example created by Raul Fuentes
 *
 * @author      Raul Fuentes <>
 * @author      Michael Morscher, <morscher@hm.edu>
 *
 * @}
 */

#include <stdio.h>
#include "xtimer.h"
#include "thread.h"

// networking
#include "msg.h"
#include "net/af.h"
#include "net/conn/udp.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/netif.h"

// application
#include "measurement.h"

#ifdef WITH_TINYDTLS
#include "dtls-base.h"
#endif

#ifdef RIOT_SHELL
#include "shell.h"
static const shell_command_t shell_commands[] = {
#ifdef WITH_CLIENT
    { "client", "Start a DTLS client (with echo)", client_thread_create },
#endif
#ifdef WITH_SERVER
	{ "server", "Start a DTLS server listening to port 7777", start_server },
#endif
    { NULL, NULL, NULL }
};
#endif

static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void)
{
	// Message queue is needed for many packets at once
	msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

	// Enable GPIO if wanted
#ifdef GPIO_OUTPUT_ENABLE
	printf("Configuring GPIOs... ");
    measurement_init_gpio();
    printf("Done!\n");
#endif

#ifdef DEVELHELP
    // Print local IP address
    printf("Waiting for IP: ");
	kernel_pid_t interface[GNRC_NETIF_NUMOF];
	char ipAddress[IPV6_ADDR_MAX_STR_LEN];
	ipv6_addr_t ipAddressTargetOpenmote;
	ipv6_addr_t ipAddressTargetCc2538dk;
	ipv6_addr_from_str(&ipAddressTargetOpenmote, "fd00::212:4b00:430:5425");
	ipv6_addr_from_str(&ipAddressTargetCc2538dk, "fd00::212:4b00:615:a86b");
	size_t numberOfInterfaces = gnrc_netif_get(interface);

	// Ensure existing interface
	if (numberOfInterfaces > 0) {

		// Wait until valid IP address is assigned
		while(1){
			if(ipv6_addr_equal(gnrc_ipv6_netif_find_addr(interface[0], &ipAddressTargetOpenmote), &ipAddressTargetOpenmote)){
				ipv6_addr_to_str(ipAddress, &ipAddressTargetOpenmote, IPV6_ADDR_MAX_STR_LEN);
				printf("%s\n", ipAddress);
				break;
			}
			if(ipv6_addr_equal(gnrc_ipv6_netif_find_addr(interface[0], &ipAddressTargetCc2538dk), &ipAddressTargetCc2538dk)){
				ipv6_addr_to_str(ipAddress, &ipAddressTargetCc2538dk, IPV6_ADDR_MAX_STR_LEN);
				printf("%s\n", ipAddress);
				break;
			}
		}
	}
#endif

	// Start shell if configured or do autostart of application
#ifdef RIOT_SHELL
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
#else
#ifdef WITH_SERVER
    server_thread_create(0, NULL);
#endif
#ifdef WITH_CLIENT
    // Wait for certain amount to debounce start up period
	xtimer_sleep(4);
    client_thread_create(0, NULL);
#endif
#endif

    return 0;
}
