# name of your application
APPLICATION = edhoc_coap_riot

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# While RIOT is flexible here, our rust_riotmodules go through Cargo.toml, and that lacks the same flexibility.
RIOTBASE = $(CURDIR)/RIOT/

CFLAGS += -DTHREAD_STACKSIZE_MAIN=20000

# Basic networking, and gcoap
USEMODULE += gcoap # just here because it pulls some useful depdenencies that enable riot_wrappers::socket_embedded_nal
USEMODULE += netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += sock_aux_local

USEMODULE += ztimer
USEMODULE += ztimer_usec
USEMODULE += ztimer_msec
USEMODULE += ztimer_sec

USEMODULE += vfs
USEMODULE += constfs

USEMODULE += prng_sha256prng

# crypto backend for edhoc-rs
EDHOC_RS_DIR ?= $(CURDIR)/../..
INCLUDES += -I$(EDHOC_RS_DIR)/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/include
ARCHIVES += $(EDHOC_RS_DIR)/crypto/edhoc-crypto-cryptocell310-sys/vendor/nrf_cc310/lib/cortex-m4/hard-float/no-interrupts/libnrf_cc310_0.9.13.a

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# Add 3k extra stack: The Rust examples take more of it than gcoap expects,
# presumably because the example use the standard library's sting formatting
# instead of one of the more optimized formatters.
CFLAGS += -DGCOAP_STACK_SIZE='(THREAD_STACKSIZE_DEFAULT+DEBUG_EXTRA_STACKSIZE+sizeof(coap_pkt_t)+1024)'

# The name of crate (as per Cargo.toml package name, but with '-' replaced with '_')
APPLICATION_RUST_MODULE = edhoc_coap_riot
BASELIBS += $(APPLICATION_RUST_MODULE).module

FEATURES_REQUIRED += rust_target

CARGO_CHANNEL ?= nightly

# Currently unknown, something related to the LED_PORT definition that doesn't
# pass C2Rust's transpilation
BOARD_BLACKLIST := ek-lm4f120xl

include $(RIOTBASE)/Makefile.include
