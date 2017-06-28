# name of your application
APPLICATION = coaps

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# TinyDTLS only has support for 32-bit architectures ATM
BOARD_BLACKLIST := arduino-duemilanove arduino-mega2560 arduino-uno chronos \
                   msb-430 msb-430h telosb waspmote-pro wsn430-v1_3b wsn430-v1_4 \
                   z1 \
                   nrf52dk # see #6022

BOARD_INSUFFICIENT_MEMORY := airfy-beacon calliope-mini cc2650stk maple-mini \
                             microbit nrf51dongle nrf6310 nucleo32-f031 \
                             nucleo32-f042 nucleo32-f303 nucleo32-l031 nucleo-f030 \
                             nucleo-f070 nucleo-f072 nucleo-f103 nucleo-f302 nucleo-f334 \
                             nucleo-l053 nucleo-l073 opencm904 pca10000 pca10005 \
                             spark-core stm32f0discovery weio yunjia-nrf51822

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif

# Specify the mandatory networking modules for IPv6 and sUDP
USEMODULE += gnrc_ipv6_router_default
USEMODULE += gnrc_udp
USEMODULE += gnrc_conn_udp

# Add a routing protocol
USEMODULE += gnrc_rpl
USEMODULE += auto_init_gnrc_rpl

# The following are only optional:
# This application dumps received packets to STDIO using the pktdump module
#USEMODULE += gnrc_pktdump

# Additional networking modules that can be dropped if not needed
#USEMODULE += gnrc_icmpv6_echo

# Add also the shell, some shell commands
#CFLAGS += -DRIOT_SHELL
#USEMODULE += shell
#USEMODULE += shell_commands
#USEMODULE += ps

#TinyDTLs (crypto.c) made use of pthread
ifneq ($(BOARD),native)
	USEMODULE += pthread
endif
 
# NOTE: The configuration for socket or non-socket communication in TinyDTLS.
CFLAGS += -DWITH_RIOT_GNRC

# NOTE: Minimize RAM usage
CFLAGS += -DGNRC_PKTBUF_SIZE=762 -DGNRC_IPV6_NETIF_ADDR_NUMOF=6 -DGNRC_IPV6_NC_SIZE=5

#NOTE: Configure hard coded global IPv6 address if needed
#IPV6_STATIC_LLADDR ?= '"fd00::212:4b00:430:5425"'
#CFLAGS += -DGNRC_IPV6_STATIC_LLADDR=$(IPV6_STATIC_LLADDR)

# NOTE: Add the package for TinyDTLS
USEPKG += tinydtls
CFLAGS += -DWITH_TINYDTLS

# NOTE: Add the package for YaCoAP
USEPKG += yacoap
CFLAGS += -DWITH_YACOAP

# Switch between UDP Client and Server
CFLAGS += -DWITH_CLIENT
CFLAGS += -DWITH_CLIENT_PUT
#CFLAGS += -DWITH_SERVER

# Switch GPIO Output/Hardware
#CFLAGS += -DHARDWARE_OPENMOTE
CFLAGS += -DGPIO_OUTPUT_ENABLE
CFLAGS += -DGPIO_OUTPUT_ENABLE_LEDS

# NOTE: Those are taken from TinyDTLS. As the original Makefiles are
#      overwitten is a good idea to preserve them here.
CFLAGS += -DDTLSv12 -DWITH_SHA256 -DDTLS_PSK

# NOTE: If enabled TinyDTLS' log are disabled (if memory is a issue).
CFLAGS += -DNDEBUG
#CFLAGS += -DYACOAP_DEBUG
CFLAGS += -DWITH_CONSOLE
CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
